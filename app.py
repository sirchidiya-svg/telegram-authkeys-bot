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
from urllib.parse import parse_qsl
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
MINI_APP_URL = os.getenv("WEBHOOK_URL", f"http://localhost:{PORT}").rstrip("/")

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
        raise DecryptionError("Could not decrypt stored value") from exc

UNREADABLE_PLACEHOLDER = "[could not be decrypted - see /support]"

def decrypt_row_safely(details: str, generated_key: str | None) -> tuple[str, str | None]:
    try:
        decrypted_details = decrypt_value(details)
        decrypted_key = decrypt_value(generated_key) if generated_key else None
        return decrypted_details, decrypted_key
    except DecryptionError:
        logger.error("Skipped row decryption: ENCRYPTION_KEY mismatch.")
        return UNREADABLE_PLACEHOLDER, None

# --- Telegram InitData HMAC-SHA256 Authenticator ---
def validate_telegram_data(init_data: str) -> dict | None:
    if not init_data or not TOKEN:
        return None
    try:
        parsed_data = dict(parse_qsl(init_data, strict_parsing=True))
        if "hash" not in parsed_data:
            return None
        received_hash = parsed_data.pop("hash")
        data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(parsed_data.items()))
        secret_key = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
        computed_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(computed_hash, received_hash):
            import json
            user_info = json.loads(parsed_data.get("user", "{}"))
            return user_info
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

FREE_DAILY_CREDITS = 10     
TRIAL_PERIOD_DAYS = 7       
SUBSCRIPTION_DAYS = 30      
SUBSCRIPTION_PRICE_STARS = int(os.getenv("SUBSCRIPTION_PRICE_STARS", "100"))  

PRIVACY_POLICY_URL = os.getenv("PRIVACY_POLICY_URL", "https://sirchidiya-svg.github.io/telegram-authkeys-bot/privacy-policy.html")
NUMERIC_ICON_URL = "https://sirchidiya-svg.github.io/telegram-authkeys-bot/numeric_icon.png"
ALPHA_ICON_URL = "https://sirchidiya-svg.github.io/telegram-authkeys-bot/alpha_icon.png"

DECRYPT_FAIL_MESSAGE = (
    "⚠️ I couldn't unlock that saved entry.\n\n"
    "This usually means the bot's encryption key was changed or lost. Your entry has not been deleted.\n"
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
    return [(t, *decrypt_row_safely(d, k), c, s) for t, d, k, c, s in rows]

def find_all_team_records(chat_id: int):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT title, details, generated_key, created_at, saved_by_name FROM saved_keys WHERE chat_id = %s ORDER BY created_at",
                (chat_id,),
            )
            rows = cursor.fetchall()
    return [(t, *decrypt_row_safely(d, k), c, s) for t, d, k, c, s in rows]

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
        return datetime.utcnow() < datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False

def grant_subscription(user_id: int, days: int = SUBSCRIPTION_DAYS) -> str:
    user_row = get_or_create_user(user_id)
    now = datetime.utcnow()
    current_expiry = None
    if user_row["subscription_expires"]:
        try:
            current_expiry = datetime.strptime(user_row["subscription_expires"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    base = current_expiry if current_expiry and current_expiry > now else now
    new_expiry_str = (base + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
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
    if (datetime.utcnow() - trial_start).days >= TRIAL_PERIOD_DAYS:
        return False, "🚫 Your 7-day free trial has ended.\nSubscribe to unlock 30 days of unlimited credits — see /subscribe."
    if get_today_credit_usage(user_id) >= FREE_DAILY_CREDITS:
        return False, f"🚫 You've used today's {FREE_DAILY_CREDITS} free credits.\nCome back tomorrow, or subscribe for unlimited credits — see /subscribe."
    increment_credit_usage(user_id)
    return True, ""

def credit_limit(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        allowed, reason = check_credit_allowed(update.effective_user.id)
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
        "🆓 Free users get 10 credits/day for your first 7 days\\.\n"
        "💫 Subscribers get unlimited credits for 30 days\\."
    )

def build_welcome_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🚀 Open AuthKeys Web App", web_app=WebAppInfo(url=MINI_APP_URL))],
        [InlineKeyboardButton("📋 Commands", callback_data="show_all_commands"), InlineKeyboardButton("🔒 Privacy", url=PRIVACY_POLICY_URL)]
    ])

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(build_welcome_message(), parse_mode="MarkdownV2", reply_markup=build_welcome_keyboard())

@rate_limit
@credit_limit
async def generate_numeric(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    key = generate_numeric_key()
    sent = await update.message.reply_text(
        f"🔑 Numeric Key: `{key}`",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]])
    )
    tag_generated_key(sent.chat_id, sent.message_id, key)

@rate_limit
@credit_limit
async def generate_alphanumeric(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    key = generate_alphanumeric_key()
    sent = await update.message.reply_text(
        f"🔑 Alphanumeric Key: `{key}`",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_alphanumeric")]])
    )
    tag_generated_key(sent.chat_id, sent.message_id, key)

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
        "• Launch our interactive Dashboard or use the dedicated support options below:"
    )
    keyboard = [
        [InlineKeyboardButton("🚀 Open AuthKeys Web App", web_app=WebAppInfo(url=MINI_APP_URL))],
        [InlineKeyboardButton("🛠️ Report Issue (/support)", callback_data="btn_nav_support")],
        [InlineKeyboardButton("💡 Give Feedback (/feedback)", callback_data="btn_nav_feedback")],
        [InlineKeyboardButton("💳 Payment Support (/paysupport)", callback_data="btn_nav_paysupport")],
    ]
    await update.message.reply_text(help_message, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

@rate_limit
async def save_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    parts = text.split(" ", 2)
    if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
        await update.message.reply_text("Usage: reply to a /numeric or /alphanumeric key message with:\n/save {title} {details}")
        return
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
    created_at = save_record(user_id, chat_id, saved_by_name, parts[1].strip(), parts[2].strip(), generated_key)
    await update.message.reply_text(f"Saved '{parts[1].strip()}'.\nDetails: {parts[2].strip()}\n🔑 Generated Key: {generated_key}\nCreated: {created_at}")

@rate_limit
async def find_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /find {title}\nExample: /find api1")
        return
    title = context.args[0].strip()
    team_mode = update.effective_chat.type in ("group", "supergroup") and is_sharing_enabled(update.effective_chat.id)
    try:
        record = find_record(update.effective_user.id, update.effective_chat.id, title, team_mode=team_mode)
    except DecryptionError:
        await update.message.reply_text(DECRYPT_FAIL_MESSAGE)
        return
    if not record:
        await update.message.reply_text(f"No saved entry found for title '{title}'.")
        return
    details, generated_key, created_at, saved_by_name = record
    e = html.escape
    key_txt = e(generated_key) if generated_key else "N/A"
    saved_by_line = f"Saved by: {e(saved_by_name)}\n" if team_mode else ""
    await update.message.reply_text(f"Title: {e(title)}\n{saved_by_line}Details: {e(details)}\nGenerated key: <code>{key_txt}</code>\nSaved: {e(created_at)}", parse_mode="HTML")

@rate_limit
async def delete_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: /delete {title}")
        return
    if delete_record(update.effective_user.id, update.effective_chat.id, context.args[0].strip()):
        await update.message.reply_text(f"Deleted '{context.args[0].strip()}'.")
    else:
        await update.message.reply_text(f"No entry found for '{context.args[0].strip()}'.")

@rate_limit
async def delete_all_my_data_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [InlineKeyboardButton("⚠️ Yes, delete everything", callback_data="confirm_delete_all"), InlineKeyboardButton("Cancel", callback_data="cancel_delete_all")]
    ]
    await update.message.reply_text("This will permanently delete ALL your saved entries. Are you sure?", reply_markup=InlineKeyboardMarkup(keyboard))

@rate_limit
async def export_my_data_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    team_mode = update.effective_chat.type in ("group", "supergroup") and is_sharing_enabled(update.effective_chat.id)
    try:
        records = find_all_team_records(update.effective_chat.id) if team_mode else find_all_records(update.effective_user.id, update.effective_chat.id)
    except DecryptionError:
        await update.message.reply_text(DECRYPT_FAIL_MESSAGE)
        return
    if not records:
        await update.message.reply_text("There's no saved data to export here.")
        return
    lines = ["📦 Saved data:\n"]
    for title, details, generated_key, created_at, saved_by_name in records:
        key_text = generated_key if generated_key else "N/A"
        by_line = f"Saved by: {saved_by_name}\n" if team_mode else ""
        lines.append(f"Title: {title}\n{by_line}Details: {details}\nGenerated key: {key_text}\nSaved: {created_at}\n")
    await update.message.reply_text("\n".join(lines))

@rate_limit
async def team_sharing_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if chat.type not in ("group", "supergroup"):
        await update.message.reply_text("Team sharing only applies inside group chats, not in DMs.")
        return
    if not context.args or context.args[0].lower() not in ("on", "off"):
        status = "ON ✅" if is_sharing_enabled(chat.id) else "OFF ❌"
        await update.message.reply_text(f"Team key sharing is currently {status} for this group.\nUse /team_sharing on or off.")
        return
    member = await context.bot.get_chat_member(chat.id, update.effective_user.id)
    if not member or member.status not in ("creator", "administrator"):
        await update.message.reply_text("🔒 Only group admins can toggle team sharing.")
        return
    enabled = context.args[0].lower() == "on"
    set_sharing_enabled(chat.id, enabled)
    await update.message.reply_text(f"✅ Team sharing is now {'ON' if enabled else 'OFF'} for this group.")

@rate_limit
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_row = get_or_create_user(update.effective_user.id)
    role_badge = "\n👑 Role: Administrator (Verified)" if (ADMIN_USER_ID != 0 and update.effective_user.id == ADMIN_USER_ID) else ""
    if is_subscribed(user_row):
        await update.message.reply_text(f"✅ Active subscription — unlimited credits until {user_row['subscription_expires']} UTC.{role_badge}")
        return
    days_elapsed = (datetime.utcnow() - datetime.strptime(user_row["trial_start"], "%Y-%m-%d")).days
    days_left = max(0, TRIAL_PERIOD_DAYS - days_elapsed)
    if days_left == 0:
        await update.message.reply_text(f"🚫 Your free trial has ended.\nSubscribe with /subscribe for unlimited credits.{role_badge}")
        return
    rem = max(0, FREE_DAILY_CREDITS - get_today_credit_usage(update.effective_user.id))
    await update.message.reply_text(f"🆓 Free trial: {days_left} day(s) left.\nCredits remaining today: {rem}\n{role_badge}")

@rate_limit
async def subscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await context.bot.send_invoice(
        chat_id=update.effective_chat.id,
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
                "INSERT INTO payments (charge_id, user_id, amount_stars, payload, paid_at) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (charge_id) DO NOTHING",
                (charge_id, user_id, amount_stars, payload, paid_at),
            )

@rate_limit
async def paysupport_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [[InlineKeyboardButton("💸 Request Refund", callback_data="req_refund_prompt")]]
    await update.message.reply_text(
        "💳 **Payment & Subscription Support**\n\n"
        "Here you can manage issues with Telegram Stars transactions or request a refund for an active subscription.\n\n"
        "• To request a refund on an active payment, tap the button below.\n"
        "• For technical glitches or errors, please use the /support command.\n"
        "• For general thoughts or feature suggestions, use /feedback.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

@rate_limit
async def feedback_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data["awaiting_feedback"] = True
    context.user_data.pop("awaiting_support", None)
    context.user_data.pop("awaiting_refund_reason", None)
    context.user_data.pop("admin_custom_reject_id", None)
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_feedback")]]
    await update.message.reply_text(
        "💡 **Feedback & Feature Suggestions**\n\n"
        "• **What you liked:** Which features worked well for your workflow?\n"
        "• **What you hope to see:** Any new key formats or tools?\n\n"
        "*(Note: For bug reports, please use /support instead.)*\n\n"
        "✍️ *Type your feedback below and press Send:*",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

@rate_limit
async def support_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data["awaiting_support"] = True
    context.user_data.pop("awaiting_feedback", None)
    context.user_data.pop("awaiting_refund_reason", None)
    context.user_data.pop("admin_custom_reject_id", None)
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_support")]]
    await update.message.reply_text(
        "🛠️ **Technical Support & Bug Reporting**\n\n"
        "• **1. What were you doing?**\n"
        "• **2. What happened?**\n"
        "• **3. What was expected?**\n\n"
        "📷 You may attach a screenshot showing the defect. Text description is required.\n\n"
        "✍️ *Type your issue details below and press Send:*",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )

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
    await update.message.reply_text(f"✅ Payment received! Unlimited credits active until {new_expiry} UTC.")

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
        await query.edit_message_text(f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]]))
        tag_generated_key(query.message.chat_id, query.message.message_id, key)

    elif query.data == "regenerate_alphanumeric":
        key = generate_alphanumeric_key()
        await query.edit_message_text(f"🔑 Alphanumeric Key: `{key}`", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_alphanumeric")]]))
        tag_generated_key(query.message.chat_id, query.message.message_id, key)

    elif query.data == "confirm_delete_all":
        count = delete_all_records(user_id)
        await query.edit_message_text(f"✅ Deleted {count} saved entr{'y' if count == 1 else 'ies'}.")

    elif query.data == "cancel_delete_all":
        await query.edit_message_text("Cancelled. Your data was not deleted.")

    elif query.data == "show_all_commands":
        await query.edit_message_text(full_commands_text(), reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("⬅ Back", callback_data="back_to_welcome")]]))

    elif query.data == "back_to_welcome":
        await query.edit_message_text(build_welcome_message(), parse_mode="MarkdownV2", reply_markup=build_welcome_keyboard())

    elif query.data == "btn_nav_support":
        context.user_data["awaiting_support"] = True
        context.user_data.pop("awaiting_feedback", None)
        await query.edit_message_text(
            "🛠️ **Technical Support & Bug Reporting**\n\n• Explain the issue and what you expected.\n📷 Screenshots welcome.\n\n✍️ *Type your message below:*",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="cancel_support")]]),
            parse_mode="Markdown"
        )

    elif query.data == "btn_nav_feedback":
        context.user_data["awaiting_feedback"] = True
        context.user_data.pop("awaiting_support", None)
        await query.edit_message_text(
            "💡 **Feedback & Feature Suggestions**\n\n• What did you like? What features would you like to see?\n\n✍️ *Type your feedback below:*",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="cancel_feedback")]]),
            parse_mode="Markdown"
        )

    elif query.data == "btn_nav_paysupport":
        await query.edit_message_text(
            "💳 **Payment Support**\nManage Stars transactions or request a refund:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("💸 Request Refund", callback_data="req_refund_prompt")]]),
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
        await query.edit_message_text("Dismissal cancelled. Refund remains pending.")

    elif query.data == "req_refund_prompt":
        terms_message = (
            "⚠️ **Refund Policy Terms**\n\n"
            "• Reviews take 3 to 5 business days.\n"
            "• Must demonstrate technical defect or malfunction.\n\nProceed?"
        )
        warning_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("✅ Yes, continue", callback_data="user_confirm_refund"), InlineKeyboardButton("❌ Cancel", callback_data="user_cancel_refund")]
        ])
        await query.edit_message_text(terms_message, reply_markup=warning_kb, parse_mode="Markdown")

    elif query.data == "user_cancel_refund":
        context.user_data.pop("awaiting_refund_reason", None)
        await query.edit_message_text("Refund request cancelled.")

    elif query.data == "user_confirm_refund":
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT charge_id, amount_stars, paid_at FROM payments WHERE user_id = %s ORDER BY paid_at DESC LIMIT 1", (user_id,))
                payment_record = cursor.fetchone()
        if not payment_record:
            await query.edit_message_text("⚠️ No payment record found for your account.")
            return
        context.user_data["awaiting_refund_reason"] = True
        context.user_data.pop("awaiting_feedback", None)
        context.user_data.pop("awaiting_support", None)
        await query.edit_message_text(
            "✍️ **Provide Your Refund Reason**\n\nDetail the issue encountered (Screenshots welcome):\n\nType your message now:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel Request", callback_data="user_cancel_refund")]]),
            parse_mode="Markdown"
        )

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
        await display_refund_card(query.message, int(query.data.split("_")[-1]), context)

    elif query.data.startswith("adm_warn_rf_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        req_id = int(query.data.split("_")[-1])
        confirm_kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("⚠️ Confirm & Issue Refund", callback_data=f"adm_exec_rf_{req_id}"), InlineKeyboardButton("Cancel", callback_data="adm_view_refunds")]
        ])
        await query.edit_message_text(f"⚠️ Confirm executing refund `#{req_id}`?", reply_markup=confirm_kb, parse_mode="Markdown")

    elif query.data.startswith("adm_exec_rf_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        req_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT user_id, user_name, username, charge_id, amount_stars FROM refund_requests WHERE id = %s", (req_id,))
                row = cursor.fetchone()
        if not row:
            await query.edit_message_text("❌ Request not found.")
            return
        target_uid, uname, u_handle, target_charge, amount = row
        if str(target_charge).startswith("TEST_"):
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE refund_requests SET status = 'approved' WHERE id = %s", (req_id,))
            await query.edit_message_text(f"✅ **[TEST PASS] Mock Refund Approved!**\n\nID: `#{req_id}`\nAmount: {amount} Stars", parse_mode="Markdown")
            return
        try:
            await context.bot.refund_star_payment(user_id=target_uid, telegram_payment_charge_id=target_charge)
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE refund_requests SET status = 'approved' WHERE id = %s", (req_id,))
                    cursor.execute("UPDATE users SET subscription_expires = NULL WHERE user_id = %s", (target_uid,))
                    cursor.execute("DELETE FROM payments WHERE charge_id = %s", (target_charge,))
            await query.edit_message_text(f"✅ Refund executed for `#{req_id}`.")
            if target_uid != ADMIN_USER_ID:
                try:
                    await context.bot.send_message(chat_id=target_uid, text="✅ Your refund request has been approved. Your Stars have been refunded.")
                except Exception:
                    pass
        except Exception as exc:
            await query.edit_message_text(f"❌ Telegram Refund Error: {exc}")

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
        await query.edit_message_text(f"❌ **Dismiss Refund Request: #{req_id}**\n\nChoose rejection notification mode:", reply_markup=dismiss_kb, parse_mode="Markdown")

    elif query.data.startswith("adm_fast_dismiss_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        req_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE refund_requests SET status = 'rejected', admin_notes = 'Corporate rejection sent.' WHERE id = %s RETURNING user_id, user_name, username", (req_id,))
                res = cursor.fetchone()
        if not res:
            await query.edit_message_text("❌ Request not found.")
            return
        target_uid, uname, u_handle = res
        if target_uid != ADMIN_USER_ID:
            try:
                await context.bot.send_message(chat_id=target_uid, text=build_corporate_rejection(uname, u_handle), parse_mode="HTML")
            except Exception:
                pass
        await query.edit_message_text(f"✅ Refund Request `#{req_id}` dismissed.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("📋 Back to Queue", callback_data="adm_view_refunds")]]))

    elif query.data.startswith("adm_custom_dismiss_prompt_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        req_id = int(query.data.split("_")[-1])
        context.user_data["admin_custom_reject_id"] = req_id
        await query.edit_message_text(
            f"✍️ **Custom Rejection Note for #{req_id}**\n\nType the rejection reason below and send:",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("❌ Cancel", callback_data="cancel_admin_rejection")]]),
            parse_mode="Markdown"
        )

    elif query.data.startswith("adm_fb_item_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        await display_feedback_card(query.message, int(query.data.split("_")[-1]), context)

    elif query.data.startswith("adm_fb_dismiss_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        fb_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE feedback_reports SET status = 'reviewed' WHERE id = %s", (fb_id,))
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅ Back to Queue", callback_data="adm_view_feedbacks")]])
        if query.message.photo:
            await query.message.edit_caption(caption=f"✅ Feedback report `#{fb_id}` marked reviewed.", reply_markup=back_kb)
        else:
            await query.message.edit_text(f"✅ Feedback report `#{fb_id}` marked reviewed.", reply_markup=back_kb)

    elif query.data.startswith("adm_sp_item_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        await display_support_card(query.message, int(query.data.split("_")[-1]), context)

    elif query.data.startswith("adm_sp_dismiss_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        ticket_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE support_tickets SET status = 'resolved' WHERE id = %s", (ticket_id,))
        back_kb = InlineKeyboardMarkup([[InlineKeyboardButton("⬅ Back to Tickets", callback_data="adm_view_support")]])
        if query.message.photo:
            await query.message.edit_caption(caption=f"✅ Ticket `#{ticket_id}` marked resolved.", reply_markup=back_kb)
        else:
            await query.message.edit_text(f"✅ Ticket `#{ticket_id}` marked resolved.", reply_markup=back_kb)

async def handle_user_submission(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    user_id = user.id

    if user_id == ADMIN_USER_ID and "admin_custom_reject_id" in context.user_data:
        req_id = context.user_data.pop("admin_custom_reject_id")
        custom_reason = (update.message.caption if update.message.photo else update.message.text) or "[No reason provided]"
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE refund_requests SET status = 'rejected', admin_notes = %s WHERE id = %s RETURNING user_id, user_name, username", (custom_reason, req_id))
                row = cursor.fetchone()
        if row and row[0] != ADMIN_USER_ID:
            try:
                await context.bot.send_message(chat_id=row[0], text=build_custom_rejection(row[1], row[2], custom_reason), parse_mode="HTML")
            except Exception:
                pass
        await update.message.reply_text(f"✅ Refund Request `#{req_id}` dismissed with custom reason.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("📋 Back to Queue", callback_data="adm_view_refunds")]]))
        return

    is_feedback = context.user_data.get("awaiting_feedback", False)
    is_support = context.user_data.get("awaiting_support", False)
    is_refund = context.user_data.get("awaiting_refund_reason", False)

    if not is_feedback and not is_support and not is_refund:
        return

    text_content = update.message.caption if update.message.photo else update.message.text
    photo_file_id = update.message.photo[-1].file_id if update.message.photo else None

    if not text_content or not text_content.strip():
        await update.message.reply_text("⚠️ A written explanation is required.")
        return

    user_name = user.full_name or "Anonymous"
    username_str = user.username or "None"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    if is_refund:
        context.user_data.pop("awaiting_refund_reason", None)
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT charge_id, amount_stars FROM payments WHERE user_id = %s ORDER BY paid_at DESC LIMIT 1", (user_id,))
                payment_record = cursor.fetchone()
        if not payment_record:
            await update.message.reply_text("⚠️ No payment record found.")
            return
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO refund_requests (user_id, user_name, username, charge_id, amount_stars, reason, photo_file_id, status, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s)",
                    (user_id, user_name, username_str, payment_record[0], payment_record[1], text_content.strip(), photo_file_id, timestamp)
                )
        await update.message.reply_text("✅ Refund Request submitted for review.")
        if ADMIN_USER_ID:
            await context.bot.send_message(chat_id=ADMIN_USER_ID, text=f"🚨 New Refund Request from {user_name} ({payment_record[1]} Stars). Use /admin_refunds.")
        return

    if is_feedback:
        context.user_data.pop("awaiting_feedback", None)
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO feedback_reports (user_id, user_name, username, feedback_text, photo_file_id, status, created_at) VALUES (%s, %s, %s, %s, %s, 'pending', %s)",
                    (user_id, user_name, username_str, text_content.strip(), photo_file_id, timestamp)
                )
        await update.message.reply_text("🙏 Thank you! Your feedback has been received.")
        if ADMIN_USER_ID:
            await context.bot.send_message(chat_id=ADMIN_USER_ID, text=f"💡 New Feedback from {user_name}. Use /admin_feedbacks.")
        return

    if is_support:
        context.user_data.pop("awaiting_support", None)
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO support_tickets (user_id, user_name, username, issue_text, photo_file_id, status, created_at) VALUES (%s, %s, %s, %s, %s, 'pending', %s)",
                    (user_id, user_name, username_str, text_content.strip(), photo_file_id, timestamp)
                )
        await update.message.reply_text("🛠️ Support Ticket logged. Our team is investigating.")
        if ADMIN_USER_ID:
            await context.bot.send_message(chat_id=ADMIN_USER_ID, text=f"⚠️ New Support Ticket from {user_name}. Use /admin_support.")

async def show_admin_refunds_menu(message, context: ContextTypes.DEFAULT_TYPE, is_edit=False) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, user_name, amount_stars, created_at FROM refund_requests WHERE status = 'pending' ORDER BY id DESC LIMIT 10")
            rows = cursor.fetchall()
    if not rows:
        text = "✅ **No Pending Refunds**"
        if is_edit and message.text:
            await message.edit_text(text, parse_mode="Markdown")
        else:
            await message.reply_text(text, parse_mode="Markdown")
        return
    keyboard = [[InlineKeyboardButton(f"#{r[0]}: {r[1][:12]} ({r[2]} Stars)", callback_data=f"adm_rf_item_{r[0]}")] for r in rows]
    text = f"📋 **Pending Refund Queue ({len(rows)})**"
    if is_edit and message.text:
        await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
    else:
        await message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

async def display_refund_card(message, req_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id, user_name, username, charge_id, amount_stars, reason, photo_file_id, created_at FROM refund_requests WHERE id = %s", (req_id,))
            row = cursor.fetchone()
    if not row:
        await message.reply_text("Request not found.")
        return
    uid, uname, u_handle, charge, amount, reason, photo_id, dt = row
    card = f"📄 **Refund Request Details: #{req_id}**\n\n• **User:** {html.escape(uname)} (@{u_handle})\n• **User ID:** `{uid}`\n• **Amount:** {amount} Stars\n• **Charge:** `{charge}`\n• **Date:** {dt}\n\n**Reason:**\n{html.escape(reason)}"
    kb = [
        [InlineKeyboardButton("💸 Approve Refund", callback_data=f"adm_warn_rf_{req_id}"), InlineKeyboardButton("❌ Reject / Dismiss...", callback_data=f"adm_dismiss_menu_{req_id}")],
        [InlineKeyboardButton("⬅ Back to Queue", callback_data="adm_view_refunds")]
    ]
    if photo_id:
        await context.bot.send_photo(chat_id=message.chat_id, photo=photo_id, caption=card, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
    else:
        await message.reply_text(card, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")

@rate_limit
async def admin_refunds_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return
    await show_admin_refunds_menu(update.message, context, is_edit=False)

async def show_admin_feedback_menu(message, context: ContextTypes.DEFAULT_TYPE, is_edit=False) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, user_name, created_at FROM feedback_reports WHERE status = 'pending' ORDER BY id DESC LIMIT 10")
            rows = cursor.fetchall()
    if not rows:
        empty = "✅ **No Pending Feedback**"
        if is_edit and message.text:
            await message.edit_text(empty, parse_mode="Markdown")
        else:
            await message.reply_text(empty, parse_mode="Markdown")
        return
    keyboard = [[InlineKeyboardButton(f"#{r[0]}: {r[1][:15]}", callback_data=f"adm_fb_item_{r[0]}")] for r in rows]
    text = f"📬 **Pending Feedback ({len(rows)})**"
    if is_edit and message.text:
        await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
    else:
        await message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

async def display_feedback_card(message, fb_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id, user_name, username, feedback_text, photo_file_id, created_at FROM feedback_reports WHERE id = %s", (fb_id,))
            row = cursor.fetchone()
    if not row:
        await message.reply_text("Report not found.")
        return
    uid, uname, u_handle, fb_text, photo_id, dt = row
    card = f"💡 **Feedback: #{fb_id}**\n\n• **From:** {html.escape(uname)} (@{u_handle})\n• **Date:** {dt}\n\n**Idea:**\n{html.escape(fb_text)}"
    kb = [[InlineKeyboardButton("✅ Mark Reviewed", callback_data=f"adm_fb_dismiss_{fb_id}")], [InlineKeyboardButton("⬅ Back to Queue", callback_data="adm_view_feedbacks")]]
    if photo_id:
        await context.bot.send_photo(chat_id=message.chat_id, photo=photo_id, caption=card, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
    else:
        await message.reply_text(card, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")

@rate_limit
async def admin_feedbacks_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return
    await show_admin_feedback_menu(update.message, context, is_edit=False)

async def show_admin_support_menu(message, context: ContextTypes.DEFAULT_TYPE, is_edit=False) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, user_name, created_at FROM support_tickets WHERE status = 'pending' ORDER BY id DESC LIMIT 10")
            rows = cursor.fetchall()
    if not rows:
        empty = "✅ **No Pending Support Tickets**"
        if is_edit and message.text:
            await message.edit_text(empty, parse_mode="Markdown")
        else:
            await message.reply_text(empty, parse_mode="Markdown")
        return
    keyboard = [[InlineKeyboardButton(f"#{r[0]}: {r[1][:15]}", callback_data=f"adm_sp_item_{r[0]}")] for r in rows]
    text = f"🛠️ **Pending Support Tickets ({len(rows)})**"
    if is_edit and message.text:
        await message.edit_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")
    else:
        await message.reply_text(text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode="Markdown")

async def display_support_card(message, ticket_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id, user_name, username, issue_text, photo_file_id, created_at FROM support_tickets WHERE id = %s", (ticket_id,))
            row = cursor.fetchone()
    if not row:
        await message.reply_text("Ticket not found.")
        return
    uid, uname, u_handle, issue_text, photo_id, dt = row
    card = f"🛠️ **Support Ticket: #{ticket_id}**\n\n• **From:** {html.escape(uname)} (@{u_handle})\n• **Date:** {dt}\n\n**Issue:**\n{html.escape(issue_text)}"
    kb = [[InlineKeyboardButton("✅ Mark Resolved", callback_data=f"adm_sp_dismiss_{ticket_id}")], [InlineKeyboardButton("⬅ Back to Tickets", callback_data="adm_view_support")]]
    if photo_id:
        await context.bot.send_photo(chat_id=message.chat_id, photo=photo_id, caption=card, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")
    else:
        await message.reply_text(card, reply_markup=InlineKeyboardMarkup(kb), parse_mode="Markdown")

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
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO refund_requests (user_id, user_name, username, charge_id, amount_stars, reason, photo_file_id, status, created_at) VALUES (%s, %s, %s, %s, %s, %s, NULL, 'pending', %s) RETURNING id",
                (ADMIN_USER_ID, "Test User", "testaccount", dummy_charge_id, 100, "Automated test: Testing dismiss flow.", timestamp)
            )
            req_id = cursor.fetchone()[0]
    await update.message.reply_text(f"🧪 Dummy refund request (`#{req_id}`) logged.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("📋 View Pending Refunds", callback_data="adm_view_refunds")]]))

async def set_bot_commands(application: Application) -> None:
    commands = [
        BotCommand("start", "Start bot and view guide"),
        BotCommand("numeric", "Generate 8-digit numeric key"),
        BotCommand("alphanumeric", "Generate 8-digit alphanumeric key"),
        BotCommand("status", "Check quota & subscription"),
        BotCommand("subscribe", "Get 30 days unlimited credits"),
        BotCommand("paysupport", "Payment assistance & refund requests"),
        BotCommand("support", "Report a bug or technical issue"),
        BotCommand("feedback", "Share ideas & feature suggestions"),
        BotCommand("export_my_data", "Export saved keys for this chat"),
        BotCommand("delete_all_my_data", "Wipe all saved keys"),
        BotCommand("help", "Help guide and support buttons"),
    ]
    await application.bot.set_my_commands(commands, scope=BotCommandScopeDefault())

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    error = context.error
    logger.error("Error while handling update", exc_info=error)
    if isinstance(error, DecryptionError) and isinstance(update, Update):
        try:
            if update.callback_query:
                await update.callback_query.answer(DECRYPT_FAIL_MESSAGE[:190], show_alert=True)
            elif update.effective_message:
                await update.effective_message.reply_text(DECRYPT_FAIL_MESSAGE)
        except Exception:
            pass

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
            cursor.execute("SELECT title, details, generated_key FROM saved_keys WHERE user_id = %s ORDER BY created_at DESC LIMIT 30", (user_id,))
            rows = cursor.fetchall()
    decrypted = []
    for t, d, k in rows:
        d_val, k_val = decrypt_row_safely(d, k)
        decrypted.append({"title": t, "details": d_val, "key": k_val})
    return web.json_response({"success": True, "records": decrypted})

def main() -> None:
    if not TOKEN:
        raise ValueError("TELEGRAM_TOKEN not found!")
    init_connection_pool()
    init_db()

    application = Application.builder().token(TOKEN).post_init(set_bot_commands).build()

    # User Command Handlers
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

    # Secret Admin Command Handlers
    application.add_handler(CommandHandler("admin_refunds", admin_refunds_command))
    application.add_handler(CommandHandler("admin_feedbacks", admin_feedbacks_command))
    application.add_handler(CommandHandler("admin_support", admin_support_command))
    application.add_handler(CommandHandler("test_refund", test_refund_command))

    # Interactive Callbacks & Payments
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(PreCheckoutQueryHandler(precheckout_callback))
    application.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_user_submission))
    application.add_handler(MessageHandler(filters.PHOTO, handle_user_submission))
    application.add_handler(InlineQueryHandler(inline_query_handler))
    application.add_error_handler(error_handler)

    # Combined runner for Bot (polling/webhook) + Mini App (web)
    async def start_all():
        await application.initialize()
        await application.start()

        app = web.Application()
        app.router.add_get("/", mini_app_index)
        app.router.add_get("/api/vault", mini_app_api_vault)

        if WEBHOOK_URL:
            webhook_path = "/" + WEBHOOK_PATH.lstrip("/")
            async def telegram_webhook(request: web.Request) -> web.Response:
                data = await request.json()
                await application.process_update(Update.de_json(data, application.bot))
                return web.Response()
            app.router.add_post(webhook_path, telegram_webhook)
            await application.bot.set_webhook(url=f"{WEBHOOK_URL.rstrip('/')}{webhook_path}")
        else:
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
