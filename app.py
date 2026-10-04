import logging
import os
import secrets
import string
import time
import uuid
import sys
import html
import asyncio
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
import psycopg2
from psycopg2.pool import ThreadedConnectionPool

from telegram import (
    Update,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    LabeledPrice,
    InlineQueryResultArticle,
    InputTextMessageContent,
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

UNREADABLE_PLACEHOLDER = "[could not be decrypted - see /help]"

def decrypt_row_safely(details: str, generated_key: str | None) -> tuple[str, str | None]:
    try:
        decrypted_details = decrypt_value(details)
        decrypted_key = decrypt_value(generated_key) if generated_key else None
        return decrypted_details, decrypted_key
    except DecryptionError:
        logger.error("Export skipped one saved row: decryption failed (check ENCRYPTION_KEY).")
        return UNREADABLE_PLACEHOLDER, None

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
GUEST_DAILY_CREDITS = 5  

# --- Contact / policy links & icon URLs ---
TELEGRAM_CONTACT_USERNAME = "sirchidiya"
TELEGRAM_CONTACT_URL = f"https://t.me/{TELEGRAM_CONTACT_USERNAME}"
PRIVACY_POLICY_URL = os.getenv("PRIVACY_POLICY_URL", "https://sirchidiya-svg.github.io/telegram-authkeys-bot/privacy-policy.html")
NUMERIC_ICON_URL = "https://sirchidiya-svg.github.io/telegram-authkeys-bot/numeric_icon.png"
ALPHA_ICON_URL = "https://sirchidiya-svg.github.io/telegram-authkeys-bot/alpha_icon.png"

DECRYPT_FAIL_MESSAGE = (
    "⚠️ I couldn't unlock that saved entry.\n\n"
    "This usually means the bot's encryption key was changed or lost, so older entries "
    "can't be read any more. Your entry has not been deleted.\n"
    f"Please contact @{TELEGRAM_CONTACT_USERNAME} for help."
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
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id BIGINT PRIMARY KEY,
                    trial_start TEXT NOT NULL,
                    subscription_expires TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_log (
                    user_id BIGINT NOT NULL,
                    usage_date TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, usage_date)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS generated_keys (
                    chat_id BIGINT NOT NULL,
                    message_id BIGINT NOT NULL,
                    key_value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (chat_id, message_id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS group_settings (
                    chat_id BIGINT PRIMARY KEY,
                    sharing_enabled INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS payments (
                    charge_id TEXT PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    amount_stars INTEGER NOT NULL,
                    payload TEXT,
                    paid_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
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
                    created_at TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS feedback_reports (
                    id SERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL,
                    user_name TEXT NOT NULL,
                    username TEXT,
                    feedback_text TEXT NOT NULL,
                    photo_file_id TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL
                )
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

# --- QUEUE COUNTER HELPERS ---
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

def build_welcome_message() -> str:
    return (
        "Welcome to AuthKeys Generator Bot\\! 🤖\n\n"
        "Generate secure numeric or alphanumeric keys instantly, right inside Telegram\\.\n\n"
        "*Available Commands:*\n"
        "/numeric \\- Generate a numeric 8\\-digit key\n"
        "/alphanumeric \\- Generate an alphanumeric 8\\-digit key\n"
        "/feedback \\- Send feedback, ideas, or report a bug\n"
        "/help \\- Contact support, collaboration or sponsorship\n\n"
        "*Example usage:*\n"
        "/numeric \\- Gets a key like: `47392615`\n"
        "/alphanumeric \\- Gets a key like: `K9M2L7X4`\n\n"
        "🆓 Free users get 10 credits/day for your first 7 days\\.\n"
        "💫 Subscribers get unlimited credits for 30 days\\.\n"
        "Credits are only spent by /numeric, /alphanumeric, and Regenerate — "
        "saving, finding, deleting, and exporting are always free\\.\n\n"
        f"_Created by [@{TELEGRAM_CONTACT_USERNAME}]({TELEGRAM_CONTACT_URL})_"
    )

def build_welcome_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📋 Commands", callback_data="show_all_commands"),
                InlineKeyboardButton("🔒 Privacy Policy", url=PRIVACY_POLICY_URL),
            ]
        ]
    )

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
        "/feedback - Submit concise feedback or report bugs\n"
        "/team_sharing on|off - Toggle team key sharing for this group\n"
        "/help - Contact support, collaboration or sponsorship\n\n"
        "🔒 Privacy: saved details and keys are encrypted in the database."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_message = (
        f"Contact [@{TELEGRAM_CONTACT_USERNAME}]({TELEGRAM_CONTACT_URL}) "
        "for support, collaboration or sponsorship\\."
    )
    keyboard = [[InlineKeyboardButton("💬 Message", url=TELEGRAM_CONTACT_URL)]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(help_message, parse_mode="MarkdownV2", reply_markup=reply_markup)

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

# --- REFINED /paysupport (FOCUSED SOLELY ON PAYMENT & REFUNDS) ---
@rate_limit
async def paysupport_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [
            InlineKeyboardButton("💸 Request Refund", callback_data="req_refund_prompt"),
            InlineKeyboardButton("❓ Contact Billing", url=TELEGRAM_CONTACT_URL),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "💳 **Payment & Subscription Support**\n\n"
        "Here you can manage issues with Telegram Stars transactions or request a refund for an active subscription.\n\n"
        "Tap below to begin a refund request or contact support directly.",
        reply_markup=reply_markup,
        parse_mode="Markdown"
    )

# --- STANDALONE /feedback COMMAND ---
@rate_limit
async def feedback_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data["awaiting_feedback"] = True
    context.user_data.pop("awaiting_refund_reason", None)
    
    keyboard = [[InlineKeyboardButton("❌ Cancel", callback_data="cancel_feedback")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    instruction = (
        "💡 **Submit Feedback or Report an Issue**\n\n"
        "We appreciate your help in improving AuthKeys Bot! To ensure we understand your report clearly:\n\n"
        "• **Be specific:** Explain what you did, what you expected, and what actually occurred.\n"
        "• **Text is required:** A written explanation must accompany any submission.\n"
        "• **Screenshots are optional:** You can attach an image/screenshot, but ensure your message contains the explanation in the caption.\n\n"
        "✍️ *Type your feedback below and press Send:*"
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

# --- INLINE QUERY HANDLER ---
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

    elif query.data == "cancel_feedback":
        context.user_data.pop("awaiting_feedback", None)
        await query.edit_message_text("Feedback submission cancelled.")

    # --- REFUND FLOW WITH TERMS AND PROMPT ---
    elif query.data == "req_refund_prompt":
        warning_kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Yes, continue", callback_data="user_confirm_refund"),
                InlineKeyboardButton("❌ No, cancel", callback_data="user_cancel_refund"),
            ]
        ])
        terms_message = (
            "⚠️ **Important Refund Policy Terms**\n\n"
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

    # --- ADMIN SPECIFIC REFUND CARD ---
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
                    "SELECT user_id, charge_id, amount_stars FROM refund_requests WHERE id = %s",
                    (req_id,)
                )
                row = cursor.fetchone()

        if not row:
            await query.edit_message_text("❌ Request record not found.")
            return

        target_uid, target_charge, amount = row

        # Handle Mock Testing Environment
        if str(target_charge).startswith("TEST_"):
            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE refund_requests SET status = 'approved' WHERE id = %s", (req_id,))
            await query.edit_message_text(
                f"✅ **[TEST PASS] Mock Refund Approved!**\n\n"
                f"• Request ID: `#{req_id}`\n"
                f"• Mock User: `{target_uid}`\n"
                f"• Amount: {amount} Stars\n"
                "Simulated refund executed successfully.",
                parse_mode="Markdown"
            )
            return

        try:
            # Live Telegram API Refund
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
                f"✅ **Refund Executed**\n\nRequest `#{req_id}` completed. {amount} Stars returned to `{target_uid}`.",
                parse_mode="Markdown"
            )

            try:
                await context.bot.send_message(
                    chat_id=target_uid,
                    text="✅ Your refund request has been approved. Your Stars have been returned to your balance."
                )
            except Exception:
                pass

        except Exception as exc:
            await query.edit_message_text(f"❌ Telegram Refund Error: {exc}")

    # --- ADMIN DISMISS REFUND ---
    elif query.data.startswith("adm_dismiss_rf_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return
        req_id = int(query.data.split("_")[-1])
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE refund_requests SET status = 'rejected' WHERE id = %s", (req_id,))
        await query.edit_message_text(f"Refund request `#{req_id}` has been marked as rejected/dismissed.")

    # --- ADMIN SPECIFIC FEEDBACK CARD ---
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
        await query.edit_message_text(f"Feedback `#{fb_id}` marked as reviewed.")

# --- INCOMING SUBMISSION HANDLER ---
async def handle_user_submission(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    user_id = user.id

    is_feedback = context.user_data.get("awaiting_feedback", False)
    is_refund = context.user_data.get("awaiting_refund_reason", False)

    if not is_feedback and not is_refund:
        return

    # Extract text content (either from text message or photo caption)
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

    # 1. PROCESS REFUND SUBMISSION
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

        # Insert into refund queue
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

        # Notify Admin with Count
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

    # 2. PROCESS FEEDBACK SUBMISSION
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
            "🙏 **Thank you!** Your feedback has been received and added to our developer queue.",
            parse_mode="Markdown"
        )

        # Notify Admin with Count
        if ADMIN_USER_ID:
            pending_count = get_pending_feedback_count()
            admin_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton(f"📬 View Feedback Reports ({pending_count})", callback_data="adm_view_feedbacks")]
            ])
            await context.bot.send_message(
                chat_id=ADMIN_USER_ID,
                text=(
                    f"📬 **New User Feedback Received!**\n\n"
                    f"• **Queue Status:** {pending_count} pending feedback report(s)\n"
                    f"• **Latest From:** {html.escape(user_name)} (`{user_id}`)\n\n"
                    "Use the button below or type `/admin_feedbacks` to review."
                ),
                reply_markup=admin_kb,
                parse_mode="Markdown"
            )

# --- ADMIN COMMANDS (HIDDEN FROM STANDARD USER MENUS) ---
async def show_admin_refunds_menu(message, context: ContextTypes.DEFAULT_TYPE, is_edit=False) -> None:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, user_name, amount_stars, created_at FROM refund_requests WHERE status = 'pending' ORDER BY id DESC LIMIT 10"
            )
            rows = cursor.fetchall()

    if not rows:
        text = "✅ **No Pending Refunds**\n\nThe refund review queue is empty."
        if is_edit:
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
    if is_edit:
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
            InlineKeyboardButton("❌ Reject / Dismiss", callback_data=f"adm_dismiss_rf_{req_id}")
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

    if not rows:
        text = "✅ **No Pending Feedback**\n\nAll feedback reports have been reviewed."
        if is_edit:
            await message.edit_text(text, parse_mode="Markdown")
        else:
            await message.reply_text(text, parse_mode="Markdown")
        return

    keyboard = []
    for fb_id, user_name, created_at in rows:
        btn_text = f"#{fb_id}: {user_name[:15]}"
        keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"adm_fb_item_{fb_id}")])

    reply_markup = InlineKeyboardMarkup(keyboard)
    text = f"📬 **Pending Feedback Queue ({len(rows)})**\nSelect any report to review:"
    if is_edit:
        await message.edit_text(text, reply_markup=reply_markup, parse_mode="Markdown")
    else:
        await message.reply_text(text, reply_markup=reply_markup, parse_mode="Markdown")

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
        f"📝 **User Feedback Report: #{fb_id}**\n\n"
        f"• **From:** {html.escape(uname)} (@{u_handle})\n"
        f"• **User ID:** `{uid}`\n"
        f"• **Submitted:** {dt}\n\n"
        f"**Message:**\n{html.escape(fb_text)}"
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

# --- TEST COMMAND FOR DUMMY REFUND SIMULATION ---
@rate_limit
async def test_refund_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != ADMIN_USER_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return

    dummy_charge_id = f"TEST_{int(time.time())}"
    dummy_user_id = 999888777
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
                (dummy_user_id, "Test User", "testaccount", dummy_charge_id, 100, "Automated test: Bot buttons unresponsive on group chats.", timestamp)
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
        "Tap the button below or type `/admin_refunds` to test reviewing and approving.",
        reply_markup=admin_kb,
        parse_mode="Markdown"
    )

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

def main() -> None:
    if not TOKEN:
        raise ValueError("TELEGRAM_TOKEN not found in environment variables!")
    
    init_connection_pool()
    init_db()

    try:
        if sys.platform.startswith("win"):
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            except Exception:
                pass
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    application = Application.builder().token(TOKEN).build()

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
    application.add_handler(CommandHandler("help", help_command))

    # Secret Admin Handlers
    application.add_handler(CommandHandler("admin_refunds", admin_refunds_command))
    application.add_handler(CommandHandler("admin_feedbacks", admin_feedbacks_command))
    application.add_handler(CommandHandler("test_refund", test_refund_command))

    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(PreCheckoutQueryHandler(precheckout_callback))
    application.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment_callback))
    
    # Text and photo submissions for feedback & refund reasons
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_user_submission))
    application.add_handler(MessageHandler(filters.PHOTO, handle_user_submission))

    application.add_handler(InlineQueryHandler(inline_query_handler))
    application.add_error_handler(error_handler)

    if WEBHOOK_URL:
        webhook_path = WEBHOOK_PATH.lstrip("/")
        webhook_url = WEBHOOK_URL.rstrip("/")
        if webhook_path:
            webhook_url = f"{webhook_url}/{webhook_path}"

        print("Starting bot using webhook...")
        application.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=webhook_path,
            webhook_url=webhook_url,
        )
    else:
        print("Starting bot using long polling mode...")
        application.run_polling()

if __name__ == "__main__":
    main()