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
    TypeHandler,
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
                CREATE TABLE IF NOT EXISTS guest_usage_log (
                    user_id BIGINT NOT NULL,
                    usage_date TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, usage_date)
                )
                """
            )

def is_sharing_enabled(chat_id: int) -> bool:
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT sharing_enabled FROM group_settings WHERE chat_id = %s", (chat_id,)
            )
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

def save_record(
    user_id: int,
    chat_id: int,
    saved_by_name: str,
    title: str,
    details: str,
    generated_key: str | None = None,
) -> str:
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    encrypted_details = encrypt_value(details)
    encrypted_key = encrypt_value(generated_key) if generated_key else None
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO saved_keys
                    (user_id, chat_id, saved_by_name, title, details, generated_key, created_at)
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
            cursor.execute(
                "SELECT key_value FROM generated_keys WHERE chat_id = %s AND message_id = %s",
                (chat_id, message_id),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return decrypt_value(row[0])

def find_record(user_id: int, chat_id: int, title: str, team_mode: bool = False):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            if team_mode:
                cursor.execute(
                    "SELECT details, generated_key, created_at, saved_by_name FROM saved_keys "
                    "WHERE chat_id = %s AND title = %s",
                    (chat_id, title),
                )
            else:
                cursor.execute(
                    "SELECT details, generated_key, created_at, saved_by_name FROM saved_keys "
                    "WHERE user_id = %s AND chat_id = %s AND title = %s",
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
            cursor.execute(
                "DELETE FROM saved_keys WHERE user_id = %s AND chat_id = %s AND title = %s",
                (user_id, chat_id, title),
            )
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
                "SELECT title, details, generated_key, created_at, saved_by_name FROM saved_keys "
                "WHERE user_id = %s AND chat_id = %s ORDER BY created_at",
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
                "SELECT title, details, generated_key, created_at, saved_by_name FROM saved_keys "
                "WHERE chat_id = %s ORDER BY created_at",
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
            cursor.execute(
                "SELECT user_id, trial_start, subscription_expires FROM users WHERE user_id = %s",
                (user_id,),
            )
            row = cursor.fetchone()
            if row:
                return {"user_id": row[0], "trial_start": row[1], "subscription_expires": row[2]}

            cursor.execute(
                "INSERT INTO users (user_id, trial_start, subscription_expires) VALUES (%s, %s, NULL)",
                (user_id, today),
            )
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
            cursor.execute(
                "UPDATE users SET subscription_expires = %s WHERE user_id = %s",
                (new_expiry_str, user_id),
            )
    return new_expiry_str

def get_today_credit_usage(user_id: int) -> int:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT count FROM usage_log WHERE user_id = %s AND usage_date = %s",
                (user_id, today),
            )
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
        return False, (
            "🚫 Your 7-day free trial has ended.\n"
            "Subscribe to unlock 30 days of unlimited credits — see /subscribe."
        )

    today_count = get_today_credit_usage(user_id)
    if today_count >= FREE_DAILY_CREDITS:
        return False, (
            f"🚫 You've used today's {FREE_DAILY_CREDITS} free credits.\n"
            f"Come back tomorrow, or subscribe for unlimited credits — see /subscribe."
        )

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

def build_welcome_message() -> str:
    return (
        "Welcome to AuthKeys Generator Bot\\! 🤖\n\n"
        "Generate secure numeric or alphanumeric keys instantly, right inside Telegram\\.\n\n"
        "*Available Commands:*\n"
        "/numeric \\- Generate a numeric 8\\-digit key\n"
        "/alphanumeric \\- Generate an alphanumeric 8\\-digit key\n"
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

    keyboard = [
        [InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    sent_message = await update.message.reply_text(
        f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup
    )
    tag_generated_key(sent_message.chat_id, sent_message.message_id, key)

@rate_limit
@credit_limit
async def generate_alphanumeric(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    key = generate_alphanumeric_key()

    keyboard = [
        [InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_alphanumeric")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    sent_message = await update.message.reply_text(
        f"🔑 Alphanumeric Key: `{key}`",
        parse_mode="Markdown",
        reply_markup=reply_markup,
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
        "/paysupport - Payment help, refund requests, and support\n"
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
    await update.message.reply_text(
        help_message, parse_mode="MarkdownV2", reply_markup=reply_markup
    )

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
        await update.message.reply_text(
            "⚠️ /save must be used as a reply to a generated key message."
        )
        return

    replied = update.message.reply_to_message
    chat_id = update.effective_chat.id
    generated_key = get_tagged_key(chat_id, replied.message_id)
    if generated_key is None:
        await update.message.reply_text(
            "⚠️ That message isn't a key this bot generated, so I can't save it."
        )
        return

    user_id = update.effective_user.id
    saved_by_name = update.effective_user.full_name or "Unknown"
    created_at = save_record(user_id, chat_id, saved_by_name, title, details, generated_key)

    key_line = f"\n🔑 Generated Key: {generated_key}" if generated_key else ""
    await update.message.reply_text(
        f"Saved '{title}'.\nDetails: {details}{key_line}\nCreated: {created_at}"
    )

def build_find_response(
    title: str, details: str, generated_key: str | None, created_at: str,
    saved_by_name: str | None = None,
) -> str:
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
    response = build_find_response(
        title, details, generated_key, created_at,
        saved_by_name=saved_by_name if team_mode else None,
    )
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
        lines.append(
            f"Title: {title}\n{saved_by_line}Details: {details}\nGenerated key: {key_text}\nSaved: {created_at}\n"
        )

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

# --- /status COMMAND WITH ADMIN BADGE FOR ADMINS ONLY ---
@rate_limit
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    user_row = get_or_create_user(user_id)

    # Check if the user is the configured admin
    is_admin = (ADMIN_USER_ID != 0 and user_id == ADMIN_USER_ID)
    role_badge = "\n👑 **Role:** Administrator (Verified)" if is_admin else ""

    if is_subscribed(user_row):
        msg = f"✅ Active subscription — unlimited credits until {user_row['subscription_expires']} UTC.{role_badge}"
        await update.message.reply_text(msg, parse_mode="Markdown" if is_admin else None)
        return

    trial_start = datetime.strptime(user_row["trial_start"], "%Y-%m-%d")
    days_elapsed = (datetime.utcnow() - trial_start).days
    days_left = max(0, TRIAL_PERIOD_DAYS - days_elapsed)

    if days_left == 0:
        msg = f"🚫 Your free trial has ended.\nSubscribe with /subscribe for 30 days of unlimited credits.{role_badge}"
        await update.message.reply_text(msg, parse_mode="Markdown" if is_admin else None)
        return

    used_today = get_today_credit_usage(user_id)
    remaining_today = max(0, FREE_DAILY_CREDITS - used_today)
    msg = f"🆓 Free trial: {days_left} day(s) left.\nCredits remaining today: {remaining_today}\n{role_badge}".rstrip()
    await update.message.reply_text(msg, parse_mode="Markdown" if is_admin else None)

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

# --- REFINED INTERACTIVE /paysupport COMMAND ---
@rate_limit
async def paysupport_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    keyboard = [
        [
            InlineKeyboardButton("💸 Request Refund", callback_data="req_refund_prompt"),
            InlineKeyboardButton("💬 Feedback & Help", url=TELEGRAM_CONTACT_URL),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "💳 **Payment & Subscription Support**\n\n"
        "How can we help you with your transaction or subscription today?",
        reply_markup=reply_markup,
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
    await update.message.reply_text(
        f"✅ Payment received! You now have unlimited credits until {new_expiry} UTC."
    )

# --- INLINE QUERY HANDLER WITH CUSTOM ICONS ---
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
        user_id = query.from_user.id
        count = delete_all_records(user_id)
        await query.edit_message_text(f"✅ Deleted {count} saved entr{'y' if count == 1 else 'ies'}.")

    elif query.data == "cancel_delete_all":
        await query.edit_message_text("Cancelled. Your data was not deleted.")

    elif query.data == "show_all_commands":
        back_keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("⬅ Back", callback_data="back_to_welcome")]])
        await query.edit_message_text(full_commands_text(), reply_markup=back_keyboard)

    elif query.data == "back_to_welcome":
        await query.edit_message_text(build_welcome_message(), parse_mode="MarkdownV2", reply_markup=build_welcome_keyboard())

    # --- USER REFUND FLOW ---
    elif query.data == "req_refund_prompt":
        warning_kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("✅ Yes, continue", callback_data="user_confirm_refund"),
                InlineKeyboardButton("❌ No, cancel", callback_data="user_cancel_refund"),
            ]
        ])
        await query.edit_message_text(
            "⚠️️ **Warning: Refund Request**\n\n"
            "Requesting a refund will cancel your active subscription and forfeit your unlimited credits.\n\n"
            "Do you want to proceed with requesting a refund?",
            reply_markup=warning_kb,
            parse_mode="Markdown"
        )

    elif query.data == "user_cancel_refund":
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

        charge_id, amount_stars, paid_at = payment_record
        user_name = query.from_user.full_name or query.from_user.username or str(user_id)

        await query.edit_message_text(
            "✅ Your refund request has been submitted to the bot administrator for review."
        )

        if ADMIN_USER_ID:
            admin_kb = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("💸 Approve Refund", callback_data=f"adm_warn_rf_{user_id}_{charge_id}"),
                    InlineKeyboardButton("Dismiss", callback_data="adm_dismiss_rf")
                ]
            ])
            admin_alert = (
                "🚨 **Incoming Refund Request**\n\n"
                f"• **User:** {user_name} (`{user_id}`)\n"
                f"• **Amount:** {amount_stars} Stars (XTR)\n"
                f"• **Charge ID:** `{charge_id}`\n"
                f"• **Paid At:** {paid_at}\n\n"
                "Tap below to review and authorize the refund."
            )
            await context.bot.send_message(
                chat_id=ADMIN_USER_ID,
                text=admin_alert,
                reply_markup=admin_kb,
                parse_mode="Markdown"
            )

    # --- ADMIN APPROVAL & SAFETY CONFIRMATION FLOW ---
    elif query.data.startswith("adm_warn_rf_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return

        _, _, _, target_uid, target_charge = query.data.split("_", 4)
        confirm_kb = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("⚠️ Yes, Issue Refund", callback_data=f"adm_exec_rf_{target_uid}_{target_charge}"),
                InlineKeyboardButton("Cancel", callback_data="adm_dismiss_rf")
            ]
        ])
        await query.edit_message_text(
            "⚠️ **ADMIN REFUND CONFIRMATION**\n\n"
            f"You are about to issue a refund for user `{target_uid}`.\n"
            "This will deduct Stars from your balance and immediately revoke their subscription.\n\n"
            "Are you sure you want to execute this refund?",
            reply_markup=confirm_kb,
            parse_mode="Markdown"
        )

    elif query.data.startswith("adm_exec_rf_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("⛔ Unauthorized.", show_alert=True)
            return

        _, _, _, target_uid_str, target_charge = query.data.split("_", 4)
        target_uid = int(target_uid_str)

        try:
            await context.bot.refund_star_payment(
                user_id=target_uid,
                telegram_payment_charge_id=target_charge
            )

            with get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE users SET subscription_expires = NULL WHERE user_id = %s", (target_uid,))
                    cursor.execute("DELETE FROM payments WHERE charge_id = %s", (target_charge,))

            await query.edit_message_text(
                f"✅ **Refund Completed**\n\nUser `{target_uid}` has been refunded and their subscription revoked.",
                parse_mode="Markdown"
            )

            try:
                await context.bot.send_message(
                    chat_id=target_uid,
                    text="✅ Your refund request has been approved. Your Stars have been refunded to your Telegram balance."
                )
            except Exception:
                pass

        except Exception as exc:
            await query.edit_message_text(f"❌ Refund execution failed: {exc}")

    elif query.data == "adm_dismiss_rf":
        await query.edit_message_text("Refund request dismissed.")

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
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(PreCheckoutQueryHandler(precheckout_callback))
    application.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment_callback))
    
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