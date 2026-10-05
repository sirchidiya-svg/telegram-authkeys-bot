import logging
import os
import secrets
import string
import time
import uuid
import sys
import html
import asyncio
import hmac
import hashlib
from urllib.parse import parse_qsl, unquote
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from aiohttp import web

from telegram import (
    Update,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    LabeledPrice,
    InlineQueryResultArticle,
    InputTextMessageContent,
    BotCommand,
    BotCommandScopeDefault,
    WebAppInfo,
    MenuButtonWebApp,
    MenuButtonCommands,
)
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    PreCheckoutQueryHandler,
    MessageHandler,
    InlineQueryHandler,
    filters,
)

logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("authkeys")

# Load environment variables
load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "webhook")
PORT = int(os.getenv("PORT", "8443"))
DATABASE_URL = os.getenv("DATABASE_URL")
ADMIN_USER_ID = int(os.getenv("ADMIN_USER_ID", "0"))

# Determine clean Mini App HTTPS URL
RAW_MINI_APP_URL = os.getenv("WEBHOOK_URL", "").strip().rstrip("/")
MINI_APP_URL = RAW_MINI_APP_URL if RAW_MINI_APP_URL.startswith("https://") else ""

# --- Encryption setup ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY not found in environment variables!")
FERNET = Fernet(ENCRYPTION_KEY.encode())

def encrypt_value(value: str) -> str:
    return FERNET.encrypt(value.encode()).decode()

class DecryptionError(Exception):
    """A saved value could not be decrypted with the current ENCRYPTION_KEY."""

def decrypt_value(value: str) -> str:
    try:
        return FERNET.decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise DecryptionError("Could not decrypt a stored value (wrong/changed key or corrupted data)") from exc

UNREADABLE_PLACEHOLDER = "[could not be decrypted - see /support]"

def decrypt_row_safely(details: str, generated_key: str | None) -> tuple[str, str | None]:
    try:
        decrypted_details = decrypt_value(details)
        decrypted_key = decrypt_value(generated_key) if generated_key else None
        return decrypted_details, decrypted_key
    except DecryptionError:
        logger.error("Export skipped one saved row: decryption failed (check ENCRYPTION_KEY).")
        return UNREADABLE_PLACEHOLDER, None

# --- Telegram InitData HMAC-SHA256 Authenticator ---
def validate_telegram_data(init_data: str) -> dict | None:
    if not init_data or not TOKEN:
        return None
    try:
        parsed_data = dict(parse_qsl(init_data, keep_blank_values=True))
        if "hash" not in parsed_data:
            return None
        received_hash = parsed_data.pop("hash")
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed_data.items()))
        secret_key = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
        computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(computed_hash, received_hash):
            import json
            return json.loads(parsed_data.get("user", "{}"))
        return None
    except Exception as e:
        logger.warning(f"Failed initData validation: {e}")
        return None

# --- Database Pool Setup ---
DB_POOL = None

def init_connection_pool():
    global DB_POOL
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL not found in environment variables!")
    DB_POOL = ThreadedConnectionPool(1, 20, dsn=DATABASE_URL)

@contextmanager
def get_db_connection():
    conn = DB_POOL.getconn()
    try:
        with conn:
            yield conn
    finally:
        DB_POOL.putconn(conn)

# --- Rate limiting setup ---
RATE_LIMIT_SECONDS = 3
_last_command_time: dict[int, float] = {}

def rate_limit(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        now = time.monotonic()
        last_time = _last_command_time.get(user_id, 0)
        if now - last_time < RATE_LIMIT_SECONDS:
            wait = round(RATE_LIMIT_SECONDS - (now - last_time), 1)
            await update.message.reply_text(f"⏳ Please wait {wait}s before trying again.")
            return
        _last_command_time[user_id] = now
        return await func(update, context)
    return wrapper

# --- Credit plan setup ---
FREE_DAILY_CREDITS = 10     
TRIAL_PERIOD_DAYS = 7       
SUBSCRIPTION_DAYS = 30      
SUBSCRIPTION_PRICE_STARS = int(os.getenv("SUBSCRIPTION_PRICE_STARS", "100"))  

# --- Contact / policy links & icon URLs ---
PRIVACY_POLICY_URL = os.getenv("PRIVACY_POLICY_URL", "https://sirchidiya-svg.github.io/telegram-authkeys-bot/privacy-policy.html")
NUMERIC_ICON_URL = "https://sirchidiya-svg.github.io/telegram-authkeys-bot/numeric_icon.png"
ALPHA_ICON_URL = "https://sirchidiya-svg.github.io/telegram-authkeys-bot/alpha_icon.png"

DECRYPT_FAIL_MESSAGE = (
    "⚠ I couldn't unlock that saved entry.\n\n"
    "This usually means the bot's encryption key was changed or lost, so older entries "
    "can't be read any more. Your entry has not been deleted.\n"
    "Please send an issue report using /support for assistance."
)

def build_corporate_rejection(user_name: str, username_str: str) -> str:
    handle_part = f" (@{username_str})" if username_str and username_str != "None" else ""
    return (
        f"Dear {html.escape(user_name)}{handle_part},\n\n"
        "Thank you for contacting AuthKeys Support regarding your recent refund request.\n\n"
        "Our administrative team has thoroughly audited your account, server uptime logs, and transaction details. "
        "Following our review against our terms of service, we found all services functioning properly with no technical "
        "faults or system defects detected.\n\n"
        "As outlined in our refund guidelines prior to submission, refund requests must demonstrate verifiable technical "
        "defects or unresolvable service interruptions. Consequently, we are unable to approve a refund at this time, "
        "and your subscription remains fully active.\n\n"
        "If you require further assistance or clarification, please reach out via /support."
    )

def build_custom_rejection(user_name: str, username_str: str, custom_reason: str) -> str:
    handle_part = f" (@{username_str})" if username_str and username_str != "None" else ""
    return (
        f"Dear {html.escape(user_name)}{handle_part},\n\n"
        "Thank you for contacting AuthKeys Support regarding your recent refund request.\n\n"
        "Following review by our administration team, your refund request has not been approved for the following reason:\n\n"
        f"💬 <i>\"{html.escape(custom_reason)}\"</i>\n\n"
        "As a result, your subscription remains active. If you have questions or require further assistance, please reach out via /support."
    )

def generate_numeric_key(length=8):
    return "".join(secrets.choice(string.digits) for _ in range(length))

def generate_alphanumeric_key(length=8):
    all_chars = string.ascii_uppercase + string.digits
    if length < 2:
        return "".join(secrets.choice(all_chars) for _ in range(length))
    guaranteed = [secrets.choice(string.ascii_uppercase), secrets.choice(string.digits)]
    remaining = [secrets.choice(all_chars) for _ in range(length - 2)]
    key_chars = guaranteed + remaining
    secrets.SystemRandom().shuffle(key_chars)
    return "".join(key_chars)

def init_db() -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS saved_keys (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    chat_id BIGINT,
                    saved_by_name TEXT,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    generated_key TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, chat_id, title)
                );
                CREATE TABLE IF NOT EXISTS users (
                    user_id BIGINT PRIMARY KEY,
                    trial_start TEXT NOT NULL,
                    subscription_expires TEXT
                );
                CREATE TABLE IF NOT EXISTS usage_log (
                    user_id BIGINT NOT NULL,
                    usage_date TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, usage_date)
                );
                CREATE TABLE IF NOT EXISTS generated_keys (
                    chat_id BIGINT NOT NULL,
                    message_id BIGINT NOT NULL,
                    key_value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (chat_id, message_id)
                );
                CREATE TABLE IF NOT EXISTS group_settings (
                    chat_id BIGINT PRIMARY KEY,
                    sharing_enabled INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS payments (
                    charge_id TEXT PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    amount_stars INTEGER NOT NULL,
                    payload TEXT,
                    paid_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS refund_requests (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    user_name TEXT NOT NULL,
                    username TEXT,
                    charge_id TEXT NOT NULL,
                    amount_stars INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    photo_file_id TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    admin_notes TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS feedback_reports (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    user_name TEXT NOT NULL,
                    username TEXT,
                    feedback_text TEXT NOT NULL,
                    photo_file_id TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS support_tickets (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    user_name TEXT NOT NULL,
                    username TEXT,
                    issue_text TEXT NOT NULL,
                    photo_file_id TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL
                );
                """
            )
            cursor.execute("ALTER TABLE refund_requests ADD COLUMN IF NOT EXISTS admin_notes TEXT")

def is_sharing_enabled(chat_id: int) -> bool:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT sharing_enabled FROM group_settings WHERE chat_id = %s", (chat_id,))
            row = cursor.fetchone()
            return bool(row[0]) if row else False

def set_sharing_enabled(chat_id: int, enabled: bool) -> None:
    updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO group_settings (chat_id, sharing_enabled, updated_at) VALUES (%s, %s, %s)
                ON CONFLICT(chat_id) DO UPDATE SET sharing_enabled = EXCLUDED.sharing_enabled, updated_at = EXCLUDED.updated_at
                """,
                (chat_id, 1 if enabled else 0, updated_at),
            )

def save_record(user_id: int, chat_id: int, saved_by_name: str, title: str, details: str, generated_key: str | None = None) -> str:
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    encrypted_details = encrypt_value(details)
    encrypted_key = encrypt_value(generated_key) if generated_key else None
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO saved_keys (user_id, chat_id, saved_by_name, title, details, generated_key, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id, chat_id, title) DO UPDATE SET
                    saved_by_name = EXCLUDED.saved_by_name,
                    details = EXCLUDED.details,
                    generated_key = EXCLUDED.generated_key,
                    created_at = EXCLUDED.created_at
                """,
                (user_id, chat_id, saved_by_name, title, encrypted_details, encrypted_key, created_at),
            )
    return created_at

def tag_generated_key(chat_id: int, message_id: int, key_value: str) -> None:
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    encrypted_key = encrypt_value(key_value)
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO generated_keys (chat_id, message_id, key_value, created_at) VALUES (%s, %s, %s, %s)
                ON CONFLICT(chat_id, message_id) DO UPDATE SET key_value = EXCLUDED.key_value, created_at = EXCLUDED.created_at
                """,
                (chat_id, message_id, encrypted_key, created_at),
            )

def get_tagged_key(chat_id: int, message_id: int) -> str | None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT key_value FROM generated_keys WHERE chat_id = %s AND message_id = %s", (chat_id, message_id))
            row = cursor.fetchone()
            if not row:
                return None
            return decrypt_value(row[0])

def find_record(user_id: int, chat_id: int, title: str, team_mode: bool = False):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            if team_mode:
                cursor.execute(
                    "SELECT details, generated_key, created_at, saved_by_name FROM saved_keys WHERE chat_id = %s AND title = %s",
                    (chat_id, title),
                )
            else:
                cursor.execute(
                    "SELECT details, generated_key, created_at, saved_by_name FROM saved_keys WHERE user_id = %s AND chat_id = %s AND title = %s",
                    (user_id, chat_id, title),
                )
            row = cursor.fetchone()
            if not row:
                return None
            details, generated_key, created_at, saved_by_name = row
            decrypted_details = decrypt_value(details)
            decrypted_key = decrypt_value(generated_key) if generated_key else None
            return decrypted_details, decrypted_key, created_at, saved_by_name

def delete_record(user_id: int, chat_id: int, title: str) -> bool:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM saved_keys WHERE user_id = %s AND chat_id = %s AND title = %s", (user_id, chat_id, title))
            return cursor.rowcount > 0

def delete_all_records(user_id: int) -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM saved_keys WHERE user_id = %s", (user_id,))
            return cursor.rowcount

def find_all_records(user_id: int, chat_id: int):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT title, details, generated_key, created_at, saved_by_name FROM saved_keys WHERE user_id = %s AND chat_id = %s ORDER BY created_at",
                (user_id, chat_id),
            )
            rows = cursor.fetchall()

    decrypted_rows = []
    for title, details, generated_key, created_at, saved_by_name in rows:
        decrypted_details, decrypted_key = decrypt_row_safely(details, generated_key)
        decrypted_rows.append((title, decrypted_details, decrypted_key, created_at, saved_by_name))
    return decrypted_rows

def find_all_team_records(chat_id: int):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT title, details, generated_key, created_at, saved_by_name FROM saved_keys WHERE chat_id = %s ORDER BY created_at",
                (chat_id,),
            )
            rows = cursor.fetchall()

    decrypted_rows = []
    for title, details, generated_key, created_at, saved_by_name in rows:
        decrypted_details, decrypted_key = decrypt_row_safely(details, generated_key)
        decrypted_rows.append((title, decrypted_details, decrypted_key, created_at, saved_by_name))
    return decrypted_rows

def get_or_create_user(user_id: int) -> dict:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id, trial_start, subscription_expires FROM users WHERE user_id = %s", (user_id,))
            row = cursor.fetchone()
            if row:
                return {"user_id": row[0], "trial_start": row[1], "subscription_expires": row[2]}

            cursor.execute("INSERT INTO users (user_id, trial_start, subscription_expires) VALUES (%s, %s, NULL)", (user_id, today))
            return {"user_id": user_id, "trial_start": today, "subscription_expires": None}

def is_subscribed(user_row: dict) -> bool:
    expires = user_row.get("subscription_expires")
    if not expires:
        return False
    try:
        expires_dt = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return datetime.utcnow() < expires_dt

def grant_subscription(user_id: int, days: int = SUBSCRIPTION_DAYS) -> str:
    user_row = get_or_create_user(user_id)
    now = datetime.utcnow()

    current_expiry = None
    if user_row["subscription_expires"]:
        try:
            current_expiry = datetime.strptime(user_row["subscription_expires"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            current_expiry = None

    base = current_expiry if current_expiry and current_expiry > now else now
    new_expiry = base + timedelta(days=days)
    new_expiry_str = new_expiry.strftime("%Y-%m-%d %H:%M:%S")

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET subscription_expires = %s WHERE user_id = %s", (new_expiry_str, user_id))
    return new_expiry_str

def get_today_credit_usage(user_id: int) -> int:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT count FROM usage_log WHERE user_id = %s AND usage_date = %s", (user_id, today))
            row = cursor.fetchone()
            return row[0] if row else 0

def increment_credit_usage(user_id: int) -> None:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO usage_log (user_id, usage_date, count) VALUES (%s, %s, 1)
                ON CONFLICT(user_id, usage_date) DO UPDATE SET count = usage_log.count + 1
                """,
                (user_id, today),
            )

def check_credit_allowed(user_id: int) -> tuple[bool, str]:
    user_row = get_or_create_user(user_id)

    if is_subscribed(user_row):
        increment_credit_usage(user_id) 
        return True, ""

    trial_start = datetime.strptime(user_row["trial_start"], "%Y-%m-%d")
    days_elapsed = (datetime.utcnow() - trial_start).days

    if days_elapsed >= TRIAL_PERIOD_DAYS:
        return False, "🚫 Your 7-day free trial has ended.\nSubscribe to unlock 30 days of unlimited credits — see /subscribe."

    today_count = get_today_credit_usage(user_id)
    if today_count >= FREE_DAILY_CREDITS:
        return False, f"🚫 You've used today's {FREE_DAILY_CREDITS} free credits.\nCome back tomorrow, or subscribe for unlimited credits — see /subscribe."

    increment_credit_usage(user_id)
    return True, ""

def credit_limit(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        allowed, reason = check_credit_allowed(user_id)
        if not allowed:
            await update.message.reply_text(reason)
            return
        return await func(update, context)
    return wrapper

def get_pending_refund_count() -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM refund_requests WHERE status = 'pending'")
            row = cursor.fetchone()
            return row[0] if row else 0

def get_pending_feedback_count() -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM feedback_reports WHERE status = 'pending'")
            row = cursor.fetchone()
            return row[0] if row else 0

def get_pending_support_count() -> int:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM support_tickets WHERE status = 'pending'")
            row = cursor.fetchone()
            return row[0] if row else 0

def build_welcome_message() -> str:
    return (
        "Welcome to AuthKeys Generator Bot\\! 🤖\n\n"
        "Generate secure numeric or alphanumeric keys instantly, or launch our Web Mini App for full visual management\\.\n\n"
        "*Available Commands:*\n"
        "/numeric \\- Generate a numeric 8\\-digit key\n"
        "/alphanumeric \\- Generate an alphanumeric 8\\-digit key\n"
        "/support \\- Report a technical issue, bug, or glitch\n"
        "/feedback \\- Share what you like or suggest new features\n"
        "/help \\- Information on commands and bot usage\n\n"
        "*Example usage:*\n"
        "/numeric \\- Gets a key like: `47392615`\n"
        "/alphanumeric \\- Gets a key like: `K9M2L7X4`\n\n"
        "🆓 Free users get 10 credits/day for your first 7 days\\.\n"
        "💫 Subscribers get unlimited credits for 30 days\\.\n"
        "Credits are only spent by /numeric, /alphanumeric, and Regenerate — "
        "saving, finding, deleting, and exporting are always free\\."
    )

def build_welcome_keyboard() -> InlineKeyboardMarkup:
    buttons = []
    if MINI_APP_URL:
        buttons.append([InlineKeyboardButton("🚀 Open AuthKeys Web App", web_app=WebAppInfo(url=MINI_APP_URL))])
    
    buttons.append([
        InlineKeyboardButton("📋 Commands", callback_data="show_all_commands"),
        InlineKeyboardButton("🔒 Privacy Policy", url=PRIVACY_POLICY_URL),
    ])
    return InlineKeyboardMarkup(buttons)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        build_welcome_message(), parse_mode="MarkdownV2", reply_markup=build_welcome_keyboard()
    )

@rate_limit
@credit_limit
async def generate_numeric(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    key = generate_numeric_key()
    keyboard = [[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    sent_message = await update.message.reply_text(
        f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup
    )
    tag_generated_key(sent_message.chat_id, sent_message.message_id, key)

@rate_limit
@credit_limit
async def generate_alphanumeric(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    key = generate_alphanumeric_key()
    keyboard = [[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_alphanumeric")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    sent_message = await update.message.reply_text(
        f"🔑 Alphanumeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup
    )
    tag_generated_key(sent_message.chat_id, sent_message.message_id, key)

def full_commands_text() -> str:
    return (
        "Available Commands:\n"
        "/numeric - Generate a numeric 8-digit key\n"
        "/alphanumeric - Generate an alphanumeric 8-digit key\n"
        "/save {title} {details} - Save a key (must reply to a generated key message)\n"
        "/find {title} - Retrieve a saved key by title\n"
        "/delete {title} - Delete a saved entry by title\n"
        "/delete_all_my_data - Delete ALL your saved entries\n"
        "/export_my_data - Export saved data for THIS chat only\n"
        "/status - Check your trial/subscription status and remaining credits\n"
        "/subscribe - Get unlimited credits for 30 days\n"
        "/paysupport - Payment assistance and refund requests\n"
        "/support - Report technical problems, errors, or bugs\n"
        "/feedback - Share ideas, what you like, or suggest features\n"
        "/team_sharing on|off - Toggle team key sharing for this group\n"
        "/help - Bot help and user documentation\n\n"
        "🔒 Privacy: saved details and keys are encrypted in the database."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_message = (
        "ℹ️ **AuthKeys Help & Support**\n\n"
        "• Encountered an error, glitch, or bug? Use /support to send a report.\n"
        "• Have ideas, suggestions, or feature requests? Use /feedback.\n"
        "• Issues regarding Telegram Stars purchases or refunds? Use /paysupport.\n\n"
        "All data is zero-knowledge encrypted at rest."
    )
    
    keyboard = []
    if MINI_APP_URL:
        keyboard.append([InlineKeyboardButton("🚀 Open AuthKeys Web App", web_app=WebAppInfo(url=MINI_APP_URL))])
        
    keyboard.extend([
        [InlineKeyboardButton("🛠️ Report Issue (/support)", callback_data="btn_nav_support")],
        [InlineKeyboardButton("💡 Give Feedback (/feedback)", callback_data="btn_nav_feedback")],
        [InlineKeyboardButton("💳 Payment Support (/paysupport)", callback_data="btn_nav_paysupport")],
    ])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(help_message, parse_mode="Markdown", reply_markup=reply_markup)

@rate_limit
async def save_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    parts = text.split(" ", 2)

    if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
        await update.message.reply_text(
            "Usage: reply to a /numeric or /alphanumeric key message with:\n"
            "/save {title} {details}\nExample: /save api1 my-important-key"
        )
        return

    title = parts[1].strip()
    details = parts[2].strip()

    if not update.message.reply_to_message:
        await update.message.reply_text("⚠️ /save must be used as a reply to a generated key message.")
        return

    replied = update.message.reply_to_message
    chat_id = update.effective_chat.id
    generated_key = get_tagged_key(chat_id, replied.message_id)
    if generated_key is None:
        await update.message.reply_text("⚠️ That message isn't a key this bot generated, so I can't save it.")
        return

    user_id = update.effective_user.id
    saved_by_name = update.effective_user.full_name or "Unknown"
    created_at = save_record(user_id, chat_id, saved_by_name, title, details, generated_key)

    key_line = f"\n🔑 Generated Key: {generated_key}" if generated_key else ""
    await update.message.reply_text(f"Saved '{title}'.\nDetails: {details}{key_line}\nCreated: {created_at}")

def build_find_response(title: str, details: str, generated_key: str | None, created_at: str, saved_by_name: str | None = None) -> str:
    e = html.escape
    generated_key_text = e(generated_key) if generated_key else "N/A"
    saved_by_line = f"Saved by: {e(saved_by_name)}\n" if saved_by_name else ""
    return (
        f"Title: {e(title)}\n"
        f"{saved_by_line}"
        f"Details: {e(details)}\n"
        f"Generated key: <code>{generated_key_text}</code>\n"
        f"Saved: {e(created_at)}"
    )

@rate_limit
async def find_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /find {title}\nExample: /find api1")
        return

    title = args[0].strip()
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    chat_type = update.effective_chat.type
    team_mode = chat_type in ("group", "supergroup") and is_sharing_enabled(chat_id)

    try:
        record = find_record(user_id, chat_id, title, team_mode=team_mode)
    except DecryptionError:
        await update.message.reply_text(DECRYPT_FAIL_MESSAGE)
        return
    if not record:
        await update.message.reply_text(f"No saved entry found for title '{title}'.")
        return

    details, generated_key, created_at, saved_by_name = record
    response = build_find_response(title, details, generated_key, created_at, saved_by_name=saved_by_name if team_mode else None)
    await update.message.reply_text(response, parse_mode="HTML")

@rate_limit
async def delete_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /delete {title}\nExample: /delete api1")
        return

    title = args[0].strip()
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    deleted = delete_record(user_id, chat_id, title)

    if deleted:
        await update.message.reply_text(f"Deleted '{title}'.")
    else:
        await update.message.reply_text(f"No saved entry found for title '{title}'.")

@rate_limit
async def delete_all_my_data_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [
            InlineKeyboardButton("⚠️ Yes, delete everything", callback_data="confirm_delete_all"),
            InlineKeyboardButton("Cancel", callback_data="cancel_delete_all"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "This will permanently delete ALL your saved entries. This cannot be undone.\n\nAre you sure?",
        reply_markup=reply_markup,
    )

@rate_limit
async def export_my_data_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    chat_type = update.effective_chat.type
    team_mode = chat_type in ("group", "supergroup") and is_sharing_enabled(chat_id)

    try:
        if team_mode:
            records = find_all_team_records(chat_id)
            header = "📦 This group's shared saved data:\n"
        else:
            records = find_all_records(user_id, chat_id)
            header = "📦 Your saved data for this chat:\n"
    except DecryptionError:
        await update.message.reply_text(DECRYPT_FAIL_MESSAGE)
        return

    if not records:
        await update.message.reply_text("There's no saved data to export here.")
        return

    lines = [header]
    for title, details, generated_key, created_at, saved_by_name in records:
        key_text = generated_key if generated_key else "N/A"
        saved_by_line = f"Saved by: {saved_by_name}\n" if team_mode else ""
        lines.append(f"Title: {title}\n{saved_by_line}Details: {details}\nGenerated key: {key_text}\nSaved: {created_at}\n")

    export_text = "\n".join(lines)
    await update.message.reply_text(export_text)

@rate_limit
async def team_sharing_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await update.message.reply_text("Team sharing only applies inside group chats, not in DMs.")
        return

    args = context.args
    if not args or args[0].lower() not in ("on", "off"):
        current = is_sharing_enabled(chat.id)
        status = "ON ✅" if current else "OFF ❌"
        await update.message.reply_text(
            f"Team key sharing is currently {status} for this group.\n\n"
            "Use /team_sharing on or /team_sharing off to change it."
        )
        return

    try:
        member = await context.bot.get_chat_member(chat.id, update.effective_user.id)
    except Exception:
        member = None
    if member is None or member.status not in ("creator", "administrator"):
        await update.message.reply_text("🔒 Only group admins can turn team sharing on or off.")
        return

    enabled = args[0].lower() == "on"
    set_sharing_enabled(chat.id, enabled)
    if enabled:
        await update.message.reply_text("✅ Team sharing is now ON for this group.")
    else:
        await update.message.reply_text("❌ Team sharing is now OFF for this group.")

@rate_limit
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    user_row = get_or_create_user(user_id)

    is_admin = (ADMIN_USER_ID != 0 and user_id == ADMIN_USER_ID)
    role_badge = "\n👑 Role: Administrator (Verified)" if is_admin else ""

    if is_subscribed(user_row):
        await update.message.reply_text(
            f"✅ Active subscription — unlimited credits until {user_row['subscription_expires']} UTC.{role_badge}"
        )
        return

    trial_start = datetime.strptime(user_row["trial_start"], "%Y-%m-%d")
    days_elapsed = (datetime.utcnow() - trial_start).days
    days_left = max(0, TRIAL_PERIOD_DAYS - days_elapsed)

    if days_left == 0:
        await update.message.reply_text(
            f"🚫 Your free trial has ended.\nSubscribe with /subscribe for 30 days of unlimited credits.{role_badge}"
        )
        return

    used_today = get_today_credit_usage(user_id)
    remaining_today = max(0, FREE_DAILY_CREDITS - used_today)
    await update.message.reply_text(
        f"🆓 Free trial: {days_left} day(s) left.\n"
        f"Credits remaining today: {remaining_today}\n{role_badge}"
    )

@rate_limit
async def subscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    await context.bot.send_invoice(
        chat_id=chat_id,
        title="AuthKeys Bot — 30 Day Subscription",
        description=f"Unlimited credits on AuthKeys Bot for {SUBSCRIPTION_DAYS} days.",
        payload=f"subscription_{update.effective_user.id}",
        provider_token="",  
        currency="XTR",
        prices=[LabeledPrice("30-day subscription", SUBSCRIPTION_PRICE_STARS)],
    )

def record_payment(user_id: int, charge_id: str, amount_stars: int, payload: str | None) -> None:
    paid_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO payments (charge_id, user_id, amount_stars, payload, paid_at) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (charge_id) DO NOTHING",
                (charge_id, user_id, amount_stars, payload, paid_at),
            )

@rate_limit
async def paysupport_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [InlineKeyboardButton("💸 Request Refund", callback_data="req_refund_prompt")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "💳 **Payment & Subscription Support**\n\n"
        "Here you can manage issues with Telegram Stars transactions or request a refund for an active subscription.\n\n"
        "• To request a refund on an active payment, tap the button below.\n"
        "• For technical glitches or errors, please use the /support command.\n"
        "• For general thoughts or feature suggestions, use /feedback.",
        reply_markup=reply_markup,
        parse_mode="Markdown"
    )

@rate_limit
async def feedback_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data["awaiting_feedback"] = True
    context.user_data.pop("awaiting_support", None)
    context.user_data.pop("awaiting_refund_reason", None)
    context.user_data.pop("admin_custom_reject_id", None)
    
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_feedback")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    instruction = (
        "💡 **Feedback & Feature Suggestions**\n\n"
        "We'd love to hear how you're using AuthKeys Bot and how we can make it even better!\n\n"
        "• **What you liked:** Which features worked well for your workflow?\n"
        "• **What you hope to see:** Any new key formats, integrations, or tools you'd like added?\n"
        "• **Ideas & Experience:** Any suggestions on how to improve the bot experience?\n\n"
        "*(Note: If you are experiencing a technical bug, malfunction, or error, please use /support instead.)*\n\n"
        "✍️ *Type your feedback below and press Send:*"
    )
    await update.message.reply_text(instruction, reply_markup=reply_markup, parse_mode="Markdown")

@rate_limit
async def support_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data["awaiting_support"] = True
    context.user_data.pop("awaiting_feedback", None)
    context.user_data.pop("awaiting_refund_reason", None)
    context.user_data.pop("admin_custom_reject_id", None)

    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_support")]]
    reply_markup = InlineKeyboardMarkup(keyboard)

    instruction = (
        "🛠️ **Technical Support & Bug Reporting**\n\n"
        "To help our engineering team resolve your issue as quickly as possible, please provide a clear and precise report:\n\n"
        "• **1. What were you doing?** (e.g., Which command was run? Private chat or group?)\n"
        "• **2. What happened?** (What error message or glitch appeared?)\n"
        "• **3. What was expected?** (What should have occurred instead?)\n\n"
        "📷 **Screenshots:** You can attach a screenshot showing the error, but please ensure your message includes a description in the text or photo caption.\n\n"
        "✍️ *Type your issue details below and press Send:*"
    )
    await update.message.reply_text(instruction, reply_markup=reply_markup, parse_mode="Markdown")

async def precheckout_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.pre_checkout_query
    if query.invoice_payload.startswith("subscription_"):
        await query.answer(ok=True)
    else:
        await query.answer(ok=False, error_message="Something went wrong with your order.")

async def successful_payment_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    payment = update.message.successful_payment
    record_payment(user_id, payment.telegram_payment_charge_id, payment.total_amount, payment.invoice_payload)
    new_expiry = grant_subscription(user_id, days=SUBSCRIPTION_DAYS)
    await update.message.reply_text(
        f"✅ Payment received! You now have unlimited credits until {new_expiry} UTC."
    )

async def inline_query_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    num_key = generate_numeric_key()
    alpha_key = generate_alphanumeric_key()

    results = [
        InlineQueryResultArticle(
            id=str(uuid.uuid4()),
            title="🔑 Generate Numeric Key",
            description=f"Tap to send: {num_key}",
            thumbnail_url=NUMERIC_ICON_URL,
            thumbnail_width=128,
            thumbnail_height=128,
            input_message_content=InputTextMessageContent(f"🔑 Numeric Key: `{num_key}`", parse_mode="Markdown")
        ),
        InlineQueryResultArticle(
            id=str(uuid.uuid4()),
            title="🔑 Generate Alphanumeric Key",
            description=f"Tap to send: {alpha_key}",
            thumbnail_url=ALPHA_ICON_URL,
            thumbnail_width=128,
            thumbnail_height=128,
            input_message_content=InputTextMessageContent(f"🔑 Alphanumeric Key: `{alpha_key}`", parse_mode="Markdown")
        ),
    ]
    await update.inline_query.answer(results, cache_time=0)

def _rate_limit_wait_seconds(user_id: int) -> float | None:
    now = time.monotonic()
    last_time = _last_command_time.get(user_id, 0)
    if now - last_time < RATE_LIMIT_SECONDS:
        return round(RATE_LIMIT_SECONDS - (now - last_time), 1)
    _last_command_time[user_id] = now
    return None

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    user_id = query.from_user.id

    if query.data in ("regenerate_numeric", "regenerate_alphanumeric"):
        wait = _rate_limit_wait_seconds(user_id)
        if wait is not None:
            await query.answer(f"⏳ Please wait {wait}s before trying again.", show_alert=True)
            return

        allowed, reason = check_credit_allowed(user_id)
        if not allowed:
            await query.answer(reason, show_alert=True)
            return

    await query.answer()

    if query.data == "regenerate_numeric":
        key = generate_numeric_key()
        keyboard = [[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup)
        tag_generated_key(query.message.chat_id, query.message.message_id, key)

    elif query.data == "regenerate_alphanumeric":
        key = generate_alphanumeric_key()
        keyboard = [[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_alphanumeric")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"🔑 Alphanumeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup)
        tag_generated_key(query.message.chat_id, query.message.message_id, key)

    elif query.data == "confirm_delete_all":
        count = delete_all_records(user_id)
        await query.edit_message_text(f"✅ Deleted {count} saved entr{'y' if count == 1 else 'ies'}.")

    elif query.data == "cancel_delete_all":
        await query.edit_message_text("Cancelled. Your data was not deleted.")

    elif query.data == "show_all_commands":
        back_keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("⬅ Back", callback_data="back_to_welcome")]])
        await query.edit_message_text(full_commands_text(), reply_markup=back_keyboard)

    elif query.data == "back_to_welcome":
        await query.edit_message_text(build_welcome_message(), parse_mode="MarkdownV2", reply_markup=build_welcome_keyboard())

    elif query.data == "btn_nav_support":
        context.user_data["awaiting_support"] = True
        context.user_data.pop("awaiting_feedback", None)
        keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_support")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        instruction = (
            "🛠️ **Technical Support & Bug Reporting**\n\n"
            "• **1. What were you doing?**\n"
            "• **2. What happened?**\n"
            "• **3. What was expected?**\n\n"
            "📷 You may attach a screenshot showing the defect. Text description is required.\n\n"
            "✍️ *Type your issue details below and send:*"
        )
        await query.edit_message_text(instruction, reply_markup=reply_markup, parse_mode="Markdown")

    elif query.data == "btn_nav_feedback":
        context.user_data["awaiting_feedback"] = True
        context.user_data.pop("awaiting_support", None)
        keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_feedback")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        instruction = (
            "💡 **Feedback & Feature Suggestions**\n\n"
            "• Share what features worked well for you.\n"
            "• Suggest new features or improvements.\n\n"
            "✍️ *Type your feedback below and send:*"
        )
        await query.edit_message_text(instruction, reply_markup=reply_markup, parse_mode="Markdown")

    elif query.data == "btn_nav_paysupport":
        keyboard = [
            [InlineKeyboardButton("💸 Request Refund", callback_data="req_refund_prompt")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(
            "💳 **Payment & Subscription Support**\n\n"
            "Here you can manage issues with Telegram Stars transactions or request a refund for an active subscription.\n\n"
            "• To request a refund on an active payment, tap the button below.\n"
            "• For technical glitches or errors, please use the /support command.\n"
            "• For general thoughts or feature suggestions, use /feedback.",
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )

    elif query.data == "cancel_feedback":
        context.user_data.pop("awaiting_feedback", None)
        await query.edit_message_text("Feedback submission cancelled.")

    elif query.data == "cancel_support":
        context.user_data.pop("awaiting_support", None)
        await query.edit_message_text("Support ticket submission cancelled.")

    elif query.data == "cancel_admin_rejection":
        context.user_data.pop("admin_custom_reject_id", None)
        await query.edit_message_text("Dismissal action cancelled. Refund remains pending in queue.")

    elif query.data == "req_refund_prompt":
        warning_kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Yes, continue", callback_data="user_confirm_refund"),
                InlineKeyboardButton("❌ No, cancel", callback_data="user_cancel_refund"),
            ]
        ])
        terms_message = (
            "⚠ **Important Refund Policy Terms**\n\n"
            "Please review our policy conditions carefully before submitting:\n\n"
            "• All refund requests are individually reviewed within **3 to 5 working days**.\n"
            "• A refund is **not automatic** and cannot be granted simply upon request.\n"
            "• You **must provide a valid, verifiable reason** or report a system defect explaining why you are unsatisfied.\n"
            "• If approved, your active subscription is revoked immediately and Stars are credited back to your balance.\n\n"
            "Do you wish to proceed?"
        )
        await query.edit_message_text(terms_message, reply_markup=warning_kb, parse_mode="Markdown")

    elif query.data == "user_cancel_refund":
        context.user_data.pop("awaiting_refund_reason", None)
        await query.edit_message_text("Refund request cancelled. Your subscription remains active.")

    elif query.data == "user_confirm_refund":
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT charge_id, amount_stars, paid_at FROM payments WHERE user_id = %s ORDER BY paid_at DESC LIMIT 1",
                    (user_id,)
                )
                payment_record = cursor.fetchone()

        if not payment_record:
            await query.edit_message_text("⚠️ No payment record found for your account to refund.")
            return

        context.user_data["awaiting_refund_reason"] = True
        context.user_data.pop("awaiting_feedback", None)
        context.user_data.pop("awaiting_support", None)

        keyboard = [[InlineKeyboardButton("❌ Cancel Request", callback_data="user_cancel_refund")]]
        reply_markup = InlineKeyboardMarkup(keyboard)

        instruction = (
            "✍️ **Provide Your Refund Reason**\n\n"
            "Please write a message explaining why you are requesting a refund:\n"
            "• Detail the issue or defect encountered.\n"
            "• **Text is required.**\n"
            "• You may attach a screenshot/photo if it illustrates an error.\n\n"
            "Type your reason now and send it:"
        )
        await query.edit_message_text(instruction, reply_markup=reply_markup, parse_mode="Markdown")

    # --- ADMIN QUEUE INSPECTION CALLBACKS ---
    elif query.data == "adm_view_refunds":
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        await show_admin_refunds_menu(query.message, context, is_edit=True)

    elif query.data == "adm_view_feedbacks":
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        await show_admin_feedback_menu(query.message, context, is_edit=True)

    elif query.data == "adm_view_support":
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        await show_admin_support_menu(query.message, context, is_edit=True)

    elif query.data.startswith("adm_rf_item_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        req_id = int(query.data.split("_")[-1])
        await display_refund_card(query.message, req_id, context)

    # --- ADMIN APPROVAL TWO-STEP CONFIRMATION ---
    elif query.data.startswith("adm_warn_rf_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return

        req_id = int(query.data.split("_")[-1])
        confirm_kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("⚠️ Confirm & Issue Refund", callback_data=f"adm_exec_rf_{req_id}"),
                InlineKeyboardButton("Cancel", callback_data="adm_view_refunds")
            ]
        ])
        await query.edit_message_text(
            f"⚠️ **ADMIN SAFETY CONFIRMATION**\n\n"
            f"Are you sure you want to approve and execute refund request `#{req_id}`?\n"
            "Telegram will immediately refund the Stars to the buyer's balance.",
            reply_markup=confirm_kb,
            parse_mode="Markdown"
        )

    # --- ADMIN EXECUTE REFUND ---
    elif query.data.startswith("adm_exec_rf_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return

        req_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT user_id, user_name, username, charge_id, amount_stars FROM refund_requests WHERE id = %s",
                    (req_id,)
                )
                row = cursor.fetchone()

        if not row:
            await query.edit_message_text("❌ Request record not found.")
            return

        target_uid, uname, u_handle, target_charge, amount = row
        handle_part = f" (@{u_handle})" if u_handle and u_handle != "None" else ""

        if str(target_charge).startswith("TEST_"):
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE refund_requests SET status = 'approved' WHERE id = %s", (req_id,))
            await query.edit_message_text(
                f"✅ **[TEST PASS] Mock Refund Approved!**\n\n"
                f"• Request ID: `#{req_id}`\n"
                f"• Target User: {uname}{handle_part} (`{target_uid}`)\n"
                f"• Amount: {amount} Stars\n"
                "Simulated refund executed successfully.",
                parse_mode="Markdown"
            )
            return

        try:
            await context.bot.refund_star_payment(
                user_id=target_uid,
                telegram_payment_charge_id=target_charge
            )

            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE refund_requests SET status = 'approved' WHERE id = %s", (req_id,))
                    cursor.execute("UPDATE users SET subscription_expires = NULL WHERE user_id = %s", (target_uid,))
                    cursor.execute("DELETE FROM payments WHERE charge_id = %s", (target_charge,))

            await query.edit_message_text(
                f"✅ **Refund Executed**\n\nRequest `#{req_id}` completed. {amount} Stars returned to {uname}{handle_part} (`{target_uid}`).",
                parse_mode="Markdown"
            )

            if target_uid != ADMIN_USER_ID:
                try:
                    await context.bot.send_message(
                        chat_id=target_uid,
                        text="✅ Your refund request has been approved. Your Stars have been returned to your balance."
                    )
                except Exception:
                    pass

        except Exception as exc:
            await query.edit_message_text(f"❌ Telegram Refund Error: {exc}")

    # --- ADMIN DISMISS MENU ---
    elif query.data.startswith("adm_dismiss_menu_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        req_id = int(query.data.split("_")[-1])
        dismiss_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⚡ Fast Dismiss (Standard Notice)", callback_data=f"adm_fast_dismiss_{req_id}")],
            [InlineKeyboardButton("✍️ Dismiss with Custom Reason", callback_data=f"adm_custom_dismiss_prompt_{req_id}")],
            [InlineKeyboardButton("⬅ Back to Request", callback_data=f"adm_rf_item_{req_id}")]
        ])
        await query.edit_message_text(
            f"❌ **Dismiss Refund Request: #{req_id}**\n\n"
            "Choose how you want to notify the user of this rejection:\n\n"
            "• **Fast Dismiss:** Automatically notifies the user with our standard corporate policy template.\n"
            "• **Custom Reason:** Prompts you to type a personal explanation which will be sent to the user.",
            reply_markup=dismiss_kb,
            parse_mode="Markdown"
        )

    # --- ADMIN FAST CORPORATE DISMISS ---
    elif query.data.startswith("adm_fast_dismiss_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return

        req_id = int(query.data.split("_")[-1])
        try:
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE refund_requests SET status = 'rejected', admin_notes = 'Default corporate rejection sent.' WHERE id = %s RETURNING user_id, user_name, username",
                        (req_id,)
                    )
                    res = cursor.fetchone()

            if not res:
                await query.edit_message_text("❌ Request not found.")
                return

            target_uid, uname, u_handle = res
            handle_part = f" (@{u_handle})" if u_handle and u_handle != "None" else ""

            if target_uid != ADMIN_USER_ID:
                try:
                    await context.bot.send_message(
                        chat_id=target_uid,
                        text=build_corporate_rejection(uname, u_handle),
                        parse_mode="HTML"
                    )
                    notify_status = f"Customer {uname}{handle_part} notified via standard policy notice."
                except Exception as e:
                    logger.warning(f"Could not deliver notice to user: {e}")
                    notify_status = f"Could not notify {uname}{handle_part} (chat might be blocked)."
            else:
                notify_status = f"[TEST MODE] Customer notification simulated for {uname}{handle_part}."

            back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("📋 Back to Queue", callback_data="adm_view_refunds")]])
            await query.edit_message_text(
                f"✅ **Refund Request #{req_id} Dismissed**\n\n{notify_status}",
                reply_markup=back_kb,
                parse_mode="Markdown"
            )
        except Exception as exc:
            logger.error("Error in fast dismiss", exc_info=exc)
            await query.edit_message_text(f"❌ Error processing dismissal: {exc}")

    # --- ADMIN CUSTOM REASON PROMPT ---
    elif query.data.startswith("adm_custom_dismiss_prompt_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return

        req_id = int(query.data.split("_")[-1])
        context.user_data["admin_custom_reject_id"] = req_id
        cancel_kb = InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel Action", callback_data="cancel_admin_rejection")]])
        await query.edit_message_text(
            f"✍️ **Custom Rejection Note for Request #{req_id}**\n\n"
            "Please type out the reason for rejecting this refund request below and press Send.\n\n"
            "The bot will wrap your explanation into an official notice and dispatch it directly to the user.",
            reply_markup=cancel_kb,
            parse_mode="Markdown"
        )

    # --- ADMIN FEEDBACK HANDLERS ---
    elif query.data.startswith("adm_fb_item_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        fb_id = int(query.data.split("_")[-1])
        await display_feedback_card(query.message, fb_id, context)

    elif query.data.startswith("adm_fb_dismiss_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        fb_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE feedback_reports SET status = 'reviewed' WHERE id = %s", (fb_id,))

        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅ Back to Queue", callback_data="adm_view_feedbacks")]])
        update_text = f"✅ **Review Completed**\n\nFeedback report `#{fb_id}` marked as reviewed."

        if query.message.photo:
            await query.message.edit_caption(caption=update_text, reply_markup=back_kb, parse_mode="Markdown")
        else:
            await query.message.edit_text(text=update_text, reply_markup=back_kb, parse_mode="Markdown")

    # --- ADMIN SUPPORT TICKETS HANDLERS ---
    elif query.data.startswith("adm_sp_item_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        ticket_id = int(query.data.split("_")[-1])
        await display_support_card(query.message, ticket_id, context)

    elif query.data.startswith("adm_sp_dismiss_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        ticket_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE support_tickets SET status = 'resolved' WHERE id = %s", (ticket_id,))

        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅ Back to Tickets", callback_data="adm_view_support")]])
        update_text = f"✅ **Issue Resolved**\n\nSupport ticket `#{ticket_id}` marked as resolved."

        if query.message.photo:
            await query.message.edit_caption(caption=update_text, reply_markup=back_kb, parse_mode="Markdown")
        else:
            await query.message.edit_text(text=update_text, reply_markup=back_kb, parse_mode="Markdown")

# --- INCOMING SUBMISSION HANDLER ---
async def handle_user_submission(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    user_id = user.id

    # 1. HANDLE ADMIN TYPING A CUSTOM REJECTION REASON
    if user_id == ADMIN_USER_ID and "admin_custom_reject_id" in context.user_data:
        req_id = context.user_data.pop("admin_custom_reject_id")
        
        custom_reason = update.message.caption if update.message.photo else update.message.text
        custom_reason = custom_reason.strip() if custom_reason else "[No specific explanation provided]"

        try:
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE refund_requests SET status = 'rejected', admin_notes = %s WHERE id = %s RETURNING user_id, user_name, username",
                        (custom_reason, req_id)
                    )
                    row = cursor.fetchone()

            if not row:
                await update.message.reply_text("❌ Could not locate that refund request in the database.")
                return

            target_uid, uname, u_handle = row
            handle_part = f" (@{u_handle})" if u_handle and u_handle != "None" else ""

            if target_uid != ADMIN_USER_ID:
                try:
                    await context.bot.send_message(
                        chat_id=target_uid,
                        text=build_custom_rejection(uname, u_handle, custom_reason),
                        parse_mode="HTML"
                    )
                    delivery_status = f"Customer {uname}{handle_part} has been notified with your reason."
                except Exception as e:
                    logger.warning(f"Could not deliver custom rejection to user: {e}")
                    delivery_status = f"Could not notify {uname}{handle_part} (chat may be blocked)."
            else:
                delivery_status = f"[TEST MODE] Customer notification simulated for {uname}{handle_part}."

            back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("📋 Back to Queue", callback_data="adm_view_refunds")]])
            await update.message.reply_text(
                f"✅ **Refund Request #{req_id} Dismissed**\n\n{delivery_status}\n\n**Reason Stored:**\n<i>\"{html.escape(custom_reason)}\"</i>",
                reply_markup=back_kb,
                parse_mode="HTML"
            )
        except Exception as exc:
            logger.error("Error executing custom rejection", exc_info=exc)
            await update.message.reply_text(f"❌ Error updating refund request: {exc}")
        return

    # Check for normal user input states
    is_feedback = context.user_data.get("awaiting_feedback", False)
    is_support = context.user_data.get("awaiting_support", False)
    is_refund = context.user_data.get("awaiting_refund_reason", False)

    if not is_feedback and not is_support and not is_refund:
        return

    text_content = update.message.caption if update.message.photo else update.message.text
    photo_file_id = update.message.photo[-1].file_id if update.message.photo else None

    # ENFORCE TEXT REQUIREMENT
    if not text_content or not text_content.strip():
        await update.message.reply_text(
            "⚠️ **A written explanation is required.**\n\n"
            "Submitting a photo alone is not sufficient. Please send your message again with a description (or add it as a photo caption).",
            parse_mode="Markdown"
        )
        return

    user_name = user.full_name or "Anonymous"
    username_str = user.username or "None"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # 2. PROCESS USER REFUND REASON SUBMISSION
    if is_refund:
        context.user_data.pop("awaiting_refund_reason", None)

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT charge_id, amount_stars FROM payments WHERE user_id = %s ORDER BY paid_at DESC LIMIT 1",
                    (user_id,)
                )
                payment_record = cursor.fetchone()

        if not payment_record:
            await update.message.reply_text("⚠️ No payment record found for your account.")
            return

        charge_id, amount_stars = payment_record

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO refund_requests 
                    (user_id, user_name, username, charge_id, amount_stars, reason, photo_file_id, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s)
                    """,
                    (user_id, user_name, username_str, charge_id, amount_stars, text_content.strip(), photo_file_id, timestamp)
                )

        await update.message.reply_text(
            "✅ **Refund Request Submitted**\n\n"
            "Your request has been logged into our administration queue.\n\n"
            "• Reviews are processed within **3 to 5 working days**.\n"
            "• You will receive a direct notification once the review is completed.",
            parse_mode="Markdown"
        )

        if ADMIN_USER_ID:
            pending_count = get_pending_refund_count()
            admin_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton(f"📋 View Pending Refunds ({pending_count})", callback_data="adm_view_refunds")]
            ])
            await context.bot.send_message(
                chat_id=ADMIN_USER_ID,
                text=(
                    f"🚨 **New Refund Request Received!**\n\n"
                    f"• **Queue Status:** {pending_count} pending refund request(s)\n"
                    f"• **Latest From:** {html.escape(user_name)} (`{user_id}`)\n"
                    f"• **Amount:** {amount_stars} Stars\n\n"
                    "Use the button below or type `/admin_refunds` to review."
                ),
                reply_markup=admin_kb,
                parse_mode="Markdown"
            )
        return

    # 3. PROCESS USER FEEDBACK SUBMISSION
    if is_feedback:
        context.user_data.pop("awaiting_feedback", None)

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO feedback_reports 
                    (user_id, user_name, username, feedback_text, photo_file_id, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, 'pending', %s)
                    """,
                    (user_id, user_name, username_str, text_content.strip(), photo_file_id, timestamp)
                )

        await update.message.reply_text(
            "🙏 **Thank you!** Your feedback and feature ideas have been forwarded to the developer team.",
            parse_mode="Markdown"
        )

        if ADMIN_USER_ID:
            pending_count = get_pending_feedback_count()
            admin_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton(f"📬 View Feedback ({pending_count})", callback_data="adm_view_feedbacks")]
            ])
            await context.bot.send_message(
                chat_id=ADMIN_USER_ID,
                text=(
                    f"💡 **New Feedback / Feature Idea Received!**\n\n"
                    f"• **Queue Status:** {pending_count} pending feedback report(s)\n"
                    f"• **From:** {html.escape(user_name)} (`{user_id}`)\n\n"
                    "Use the button below or type `/admin_feedbacks` to review."
                ),
                reply_markup=admin_kb,
                parse_mode="Markdown"
            )
        return

    # 4. PROCESS TECHNICAL SUPPORT TICKET SUBMISSION
    if is_support:
        context.user_data.pop("awaiting_support", None)

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO support_tickets 
                    (user_id, user_name, username, issue_text, photo_file_id, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, 'pending', %s)
                    """,
                    (user_id, user_name, username_str, text_content.strip(), photo_file_id, timestamp)
                )

        await update.message.reply_text(
            "🛠️ **Support Ticket Received!**\n\n"
            "Your technical report has been forwarded to our engineering queue for investigation. Thank you for reporting this issue!",
            parse_mode="Markdown"
        )

        if ADMIN_USER_ID:
            pending_count = get_pending_support_count()
            admin_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton(f"🛠️ View Support Tickets ({pending_count})", callback_data="adm_view_support")]
            ])
            await context.bot.send_message(
                chat_id=ADMIN_USER_ID,
                text=(
                    f"⚠️ **New Bug / Technical Support Ticket!**\n\n"
                    f"• **Queue Status:** {pending_count} pending support ticket(s)\n"
                    f"• **From:** {html.escape(user_name)} (`{user_id}`)\n\n"
                    "Use the button below or type `/admin_support` to review."
                ),
                reply_markup=admin_kb,
                parse_mode="Markdown"
            )

# --- ADMIN DISPLAY UTILITIES ---
async def show_admin_refunds_menu(message, context: ContextTypes.DEFAULT_TYPE, is_edit=False) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, user_name, amount_stars, created_at FROM refund_requests WHERE status = 'pending' ORDER BY id DESC LIMIT 10"
            )
            rows = cursor.fetchall()

    if not rows:
        text = "✅ **No Pending Refunds**\n\nThe refund review queue is empty."
        if is_edit and message.text:
            await message.edit_text(text, parse_mode="Markdown")
        else:
            await message.reply_text(text, parse_mode="Markdown")
        return

    keyboard = []
    for req_id, user_name, amount, created_at in rows:
        btn_text = f"#{req_id}: {user_name[:12]} ({amount} Stars)"
        keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"adm_rf_item_{req_id}")])

    reply_markup = InlineKeyboardMarkup(keyboard)
    text = f"📋 **Pending Refund Queue ({len(rows)})**\nSelect any request to inspect details and take action:"
    if is_edit and message.text:
        await message.edit_text(text, reply_markup=reply_markup, parse_mode="Markdown")
    else:
        await message.reply_text(text, reply_markup=reply_markup, parse_mode="Markdown")

async def display_refund_card(message, req_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, user_name, username, charge_id, amount_stars, reason, photo_file_id, created_at FROM refund_requests WHERE id = %s",
                (req_id,)
            )
            row = cursor.fetchone()

    if not row:
        await message.reply_text("Request not found.")
        return

    uid, uname, u_handle, charge, amount, reason, photo_id, dt = row
    card = (
        f"📄 **Refund Request Details: #{req_id}**\n\n"
        f"• **User:** {html.escape(uname)} (@{u_handle})\n"
        f"• **User ID:** `{uid}`\n"
        f"• **Amount:** {amount} Stars\n"
        f"• **Charge ID:** `{charge}`\n"
        f"• **Date:** {dt}\n\n"
        f"**Reason:**\n{html.escape(reason)}"
    )

    kb = [
        [
            InlineKeyboardButton("💸 Approve Refund", callback_data=f"adm_warn_rf_{req_id}"),
            InlineKeyboardButton("❌ Reject / Dismiss...", callback_data=f"adm_dismiss_menu_{req_id}")
        ],
        [InlineKeyboardButton("⬅ Back to Queue", callback_data="adm_view_refunds")]
    ]
    reply_markup = InlineKeyboardMarkup(kb)

    if photo_id:
        await context.bot.send_photo(
            chat_id=message.chat_id,
            photo=photo_id,
            caption=card,
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )
    else:
        await message.reply_text(card, reply_markup=reply_markup, parse_mode="Markdown")

@rate_limit
async def admin_refunds_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return
    await show_admin_refunds_menu(update.message, context, is_edit=False)

async def show_admin_feedback_menu(message, context: ContextTypes.DEFAULT_TYPE, is_edit=False) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, user_name, created_at FROM feedback_reports WHERE status = 'pending' ORDER BY id DESC LIMIT 10"
            )
            rows = cursor.fetchall()

    empty_text = "✅ **No Pending Feedback**\n\nAll feedback reports have been reviewed."

    if not rows:
        if is_edit:
            if message.photo:
                await message.edit_caption(caption=empty_text, parse_mode="Markdown")
            else:
                await message.edit_text(empty_text, parse_mode="Markdown")
        else:
            await message.reply_text(empty_text, parse_mode="Markdown")
        return

    keyboard = []
    for fb_id, user_name, created_at in rows:
        btn_text = f"#{fb_id}: {user_name[:15]}"
        keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"adm_fb_item_{fb_id}")])

    reply_markup = InlineKeyboardMarkup(keyboard)
    menu_text = f"📬 **Pending Feedback Ideas ({len(rows)})**\nSelect any report to review:"

    if is_edit:
        if message.photo:
            await message.reply_text(menu_text, reply_markup=reply_markup, parse_mode="Markdown")
            try:
                await message.delete()
            except Exception:
                pass
        else:
            await message.edit_text(menu_text, reply_markup=reply_markup, parse_mode="Markdown")
    else:
        await message.reply_text(menu_text, reply_markup=reply_markup, parse_mode="Markdown")

async def display_feedback_card(message, fb_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, user_name, username, feedback_text, photo_file_id, created_at FROM feedback_reports WHERE id = %s",
                (fb_id,)
            )
            row = cursor.fetchone()

    if not row:
        await message.reply_text("Report not found.")
        return

    uid, uname, u_handle, fb_text, photo_id, dt = row
    card = (
        f"💡 **Feedback / Suggestion: #{fb_id}**\n\n"
        f"• **From:** {html.escape(uname)} (@{u_handle})\n"
        f"• **User ID:** `{uid}`\n"
        f"• **Submitted:** {dt}\n\n"
        f"**Idea / Thoughts:**\n{html.escape(fb_text)}"
    )

    kb = [
        [InlineKeyboardButton("✅ Mark Reviewed", callback_data=f"adm_fb_dismiss_{fb_id}")],
        [InlineKeyboardButton("⬅ Back to Queue", callback_data="adm_view_feedbacks")]
    ]
    reply_markup = InlineKeyboardMarkup(kb)

    if photo_id:
        await context.bot.send_photo(
            chat_id=message.chat_id,
            photo=photo_id,
            caption=card,
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )
    else:
        await message.reply_text(card, reply_markup=reply_markup, parse_mode="Markdown")

@rate_limit
async def admin_feedbacks_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return
    await show_admin_feedback_menu(update.message, context, is_edit=False)

async def show_admin_support_menu(message, context: ContextTypes.DEFAULT_TYPE, is_edit=False) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, user_name, created_at FROM support_tickets WHERE status = 'pending' ORDER BY id DESC LIMIT 10"
            )
            rows = cursor.fetchall()

    empty_text = "✅ **No Pending Support Tickets**\n\nAll reported issues have been resolved."

    if not rows:
        if is_edit:
            if message.photo:
                await message.edit_caption(caption=empty_text, parse_mode="Markdown")
            else:
                await message.edit_text(empty_text, parse_mode="Markdown")
        else:
            await message.reply_text(empty_text, parse_mode="Markdown")
        return

    keyboard = []
    for ticket_id, user_name, created_at in rows:
        btn_text = f"#{ticket_id}: {user_name[:15]}"
        keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"adm_sp_item_{ticket_id}")])

    reply_markup = InlineKeyboardMarkup(keyboard)
    menu_text = f"🛠️ **Pending Support Tickets ({len(rows)})**\nSelect any bug ticket to inspect:"

    if is_edit:
        if message.photo:
            await message.reply_text(menu_text, reply_markup=reply_markup, parse_mode="Markdown")
            try:
                await message.delete()
            except Exception:
                pass
        else:
            await message.edit_text(menu_text, reply_markup=reply_markup, parse_mode="Markdown")
    else:
        await message.reply_text(menu_text, reply_markup=reply_markup, parse_mode="Markdown")

async def display_support_card(message, ticket_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT user_id, user_name, username, issue_text, photo_file_id, created_at FROM support_tickets WHERE id = %s",
                (ticket_id,)
            )
            row = cursor.fetchone()

    if not row:
        await message.reply_text("Ticket not found.")
        return

    uid, uname, u_handle, issue_text, photo_id, dt = row
    card = (
        f"🛠️ **Bug / Support Ticket: #{ticket_id}**\n\n"
        f"• **From:** {html.escape(uname)} (@{u_handle})\n"
        f"• **User ID:** `{uid}`\n"
        f"• **Submitted:** {dt}\n\n"
        f"**Defect Details:**\n{html.escape(issue_text)}"
    )

    kb = [
        [InlineKeyboardButton("✅ Mark Resolved", callback_data=f"adm_sp_dismiss_{ticket_id}")],
        [InlineKeyboardButton("⬅ Back to Tickets", callback_data="adm_view_support")]
    ]
    reply_markup = InlineKeyboardMarkup(kb)

    if photo_id:
        await context.bot.send_photo(
            chat_id=message.chat_id,
            photo=photo_id,
            caption=card,
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )
    else:
        await message.reply_text(card, reply_markup=reply_markup, parse_mode="Markdown")

@rate_limit
async def admin_support_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return
    await show_admin_support_menu(update.message, context, is_edit=False)

@rate_limit
async def test_refund_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return

    dummy_charge_id = f"TEST_{int(time.time())}"
    dummy_user_id = ADMIN_USER_ID
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO refund_requests 
                (user_id, user_name, username, charge_id, amount_stars, reason, photo_file_id, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NULL, 'pending', %s)
                RETURNING id
                """,
                (dummy_user_id, "Test User", "testaccount", dummy_charge_id, 100, "Automated test: Testing dismiss flow and customer notifications.", timestamp)
            )
            req_id = cursor.fetchone()[0]

    pending_count = get_pending_refund_count()
    admin_kb = InlineKeyboardMarkup([
        [InlineKeyboardButton(f"📋 View Pending Refunds ({pending_count})", callback_data="adm_view_refunds")]
    ])

    await update.message.reply_text(
        f"🧪 **[TEST MOCK GENERATED]**\n\n"
        f"A dummy refund request (`#{req_id}`) has been logged!\n"
        f"• Queue count is now: **{pending_count}**\n\n"
        "Tap below to test approving or dismissing (fast or custom reason):",
        reply_markup=admin_kb,
        parse_mode="Markdown"
    )

# --- BOT COMMANDS & PERSISTENT MENU CONFIGURATION ---
async def set_bot_commands(application: Application) -> None:
    commands = [
        BotCommand("start", "Start bot and view quick-start guide"),
        BotCommand("numeric", "Generate an 8-digit numeric passkey"),
        BotCommand("alphanumeric", "Generate an 8-digit alphanumeric key"),
        BotCommand("status", "Check credits & subscription expiry"),
        BotCommand("subscribe", "Get unlimited credits for 30 days"),
        BotCommand("paysupport", "Refund requests for Telegram Stars"),
        BotCommand("support", "Report a technical bug or system defect"),
        BotCommand("feedback", "Suggest features or share your experience"),
        BotCommand("export_my_data", "Export saved keys for current chat"),
        BotCommand("delete_all_my_data", "Wipe all your saved keys"),
        BotCommand("help", "Help guide and support buttons"),
    ]
    await application.bot.set_my_commands(commands, scope=BotCommandScopeDefault())
    
    # Configure top header menu button if valid HTTPS URL exists
    if MINI_APP_URL:
        try:
            await application.bot.set_chat_menu_button(
                menu_button=MenuButtonWebApp(
                    text="⚡ Open App",
                    web_app=WebAppInfo(url=MINI_APP_URL)
                )
            )
            logger.info("Successfully registered persistent Mini App MenuButton.")
        except Exception as e:
            logger.warning(f"Could not set persistent WebApp menu button: {e}")
    else:
        try:
            await application.bot.set_chat_menu_button(menu_button=MenuButtonCommands())
        except Exception:
            pass

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    error = context.error
    logger.error("Error while handling an update", exc_info=error)

    if isinstance(error, DecryptionError) and isinstance(update, Update):
        try:
            if update.callback_query:
                await update.callback_query.answer(DECRYPT_FAIL_MESSAGE[:190], show_alert=True)
            elif update.effective_message:
                await update.effective_message.reply_text(DECRYPT_FAIL_MESSAGE)
        except Exception:
            logger.exception("Could not send the decryption error message to the user")

# --- MINI APP WEB HANDLERS ---
async def mini_app_index(request: web.Request) -> web.Response:
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if not os.path.exists(template_path):
        return web.Response(text="Mini app template not found. Place index.html inside templates/", status=404)
    with open(template_path, "r", encoding="utf-8") as f:
        return web.Response(text=f.read(), content_type="text/html")

async def mini_app_api_vault(request: web.Request) -> web.Response:
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    user_info = validate_telegram_data(init_data)
    if not user_info:
        return web.json_response({"success": False, "error": "Unauthorized Telegram session"}, status=401)
    
    user_id = user_info.get("id")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT title, details, generated_key FROM saved_keys WHERE user_id = %s ORDER BY created_at DESC LIMIT 30",
                (user_id,)
            )
            rows = cursor.fetchall()

    decrypted = []
    for t, d, k in rows:
        d_val, k_val = decrypt_row_safely(d, k)
        decrypted.append({"title": t, "details": d_val, "key": k_val})

    return web.json_response({"success": True, "records": decrypted})

async def mini_app_api_save_key(request: web.Request) -> web.Response:
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    user_info = validate_telegram_data(init_data)
    if not user_info:
        return web.json_response({"success": False, "error": "Unauthorized session"}, status=401)
    
    try:
        body = await request.json()
        title = body.get("title", "").strip()
        details = body.get("details", "").strip()
        key_value = body.get("key", "").strip()

        if not title:
            return web.json_response({"success": False, "error": "Title required"}, status=400)

        user_id = user_info.get("id")
        user_name = user_info.get("first_name", "WebUser")
        
        save_record(user_id, user_id, user_name, title, details, key_value)
        return web.json_response({"success": True})
    except Exception as e:
        logger.error(f"Error saving key via webapp: {e}")
        return web.json_response({"success": False, "error": "Database error"}, status=500)

def main() -> None:
    if not TOKEN:
        raise ValueError("TELEGRAM_TOKEN not found in environment variables!")
    
    init_connection_pool()
    init_db()

    application = Application.builder().token(TOKEN).post_init(set_bot_commands).build()

    # Public User Handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("numeric", generate_numeric))
    application.add_handler(CommandHandler("alphanumeric", generate_alphanumeric))
    application.add_handler(CommandHandler("save", save_command))
    application.add_handler(CommandHandler("find", find_command))
    application.add_handler(CommandHandler("delete", delete_command))
    application.add_handler(CommandHandler("delete_all_my_data", delete_all_my_data_command))
    application.add_handler(CommandHandler("export_my_data", export_my_data_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("team_sharing", team_sharing_command))
    application.add_handler(CommandHandler("subscribe", subscribe_command))
    application.add_handler(CommandHandler("paysupport", paysupport_command))
    application.add_handler(CommandHandler("feedback", feedback_command))
    application.add_handler(CommandHandler("support", support_command))
    application.add_handler(CommandHandler("help", help_command))

    # Secret Admin Handlers
    application.add_handler(CommandHandler("admin_refunds", admin_refunds_command))
    application.add_handler(CommandHandler("admin_feedbacks", admin_feedbacks_command))
    application.add_handler(CommandHandler("admin_support", admin_support_command))
    application.add_handler(CommandHandler("test_refund", test_refund_command))

    # Interaction & Payment Handlers
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(PreCheckoutQueryHandler(precheckout_callback))
    application.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_user_submission))
    application.add_handler(MessageHandler(filters.PHOTO, handle_user_submission))

    application.add_handler(InlineQueryHandler(inline_query_handler))
    application.add_error_handler(error_handler)

    # Combined runner: Bot polling + aiohttp web server for Mini App
    async def start_all():
        await application.initialize()
        await application.start()

        app = web.Application()
        app.router.add_get("/", mini_app_index)
        app.router.add_get("/api/vault", mini_app_api_vault)
        app.router.add_post("/api/save_key", mini_app_api_save_key)

        await application.updater.start_polling()

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", PORT)
        await site.start()
        logger.info(f"AuthKeys Server and Mini App running on port {PORT}")

        while True:
            await asyncio.sleep(3600)

    asyncio.run(start_all())

if __name__ == "__main__":
    main()
