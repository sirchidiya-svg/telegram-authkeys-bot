import os
import html
import secrets
import string
import time
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps
import asyncio
import sys
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from psycopg2 import pool as pg_pool
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
    filters,
)

# Logging configuration
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "webhook")
PORT = int(os.getenv("PORT", "8443"))
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL not found in environment variables!")

# PostgreSQL connection pool
db_pool = pg_pool.ThreadedConnectionPool(minconn=1, maxconn=10, dsn=DATABASE_URL)


def get_db_connection():
    return db_pool.getconn()


def release_db_connection(conn):
    db_pool.putconn(conn)


# Encryption setup
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY not found in environment variables!")
FERNET = Fernet(ENCRYPTION_KEY.encode())


def encrypt_value(value: str) -> str:
    return FERNET.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    return FERNET.decrypt(value.encode()).decode()


# Rate limiting setup with cleanup
RATE_LIMIT_SECONDS = 3
_last_command_time: dict[int, float] = {}


def _cleanup_rate_limiter():
    now = time.monotonic()
    stale = [uid for uid, t in _last_command_time.items() if now - t > 60]
    for uid in stale:
        del _last_command_time[uid]


def rate_limit(func):
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.effective_user or not update.message:
            return await func(update, context)
        user_id = update.effective_user.id
        now = time.monotonic()
        _cleanup_rate_limiter()
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
GUEST_DAILY_CREDITS = 5

TELEGRAM_CONTACT_USERNAME = "sirchidiya"
TELEGRAM_CONTACT_URL = f"https://t.me/{TELEGRAM_CONTACT_USERNAME}"
PRIVACY_POLICY_URL = os.getenv("PRIVACY_POLICY_URL", "https://sirchidiya-svg.github.io/telegram-authkeys-bot/privacy-policy.html")


def generate_numeric_key(length=8) -> str:
    return "".join(secrets.choice(string.digits) for _ in range(length))


def generate_alphanumeric_key(length=8) -> str:
    if length < 2:
        chars = string.ascii_uppercase + string.digits
        return "".join(secrets.choice(chars) for _ in range(length))

    all_chars = string.ascii_uppercase + string.digits
    key_chars = [secrets.choice(string.ascii_uppercase), secrets.choice(string.digits)]
    key_chars += [secrets.choice(all_chars) for _ in range(length - 2)]

    for i in range(len(key_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        key_chars[i], key_chars[j] = key_chars[j], key_chars[i]
    return "".join(key_chars)


def init_db() -> None:
    conn = get_db_connection()
    try:
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
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id BIGINT PRIMARY KEY,
                    trial_start TEXT NOT NULL,
                    subscription_expires TEXT
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_log (
                    user_id BIGINT NOT NULL,
                    usage_date TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, usage_date)
                );
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
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS group_settings (
                    chat_id BIGINT PRIMARY KEY,
                    sharing_enabled INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS guest_usage_log (
                    user_id BIGINT NOT NULL,
                    usage_date TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (user_id, usage_date)
                );
                """
            )
            conn.commit()
    finally:
        release_db_connection(conn)


def is_sharing_enabled(chat_id: int) -> bool:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT sharing_enabled FROM group_settings WHERE chat_id = %s;", (chat_id,))
            row = cursor.fetchone()
            return bool(row[0]) if row else False
    finally:
        release_db_connection(conn)


def set_sharing_enabled(chat_id: int, enabled: bool) -> None:
    updated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO group_settings (chat_id, sharing_enabled, updated_at)
                VALUES (%s, %s, %s)
                ON CONFLICT(chat_id) DO UPDATE SET
                    sharing_enabled = EXCLUDED.sharing_enabled,
                    updated_at = EXCLUDED.updated_at;
                """,
                (chat_id, 1 if enabled else 0, updated_at),
            )
            conn.commit()
    finally:
        release_db_connection(conn)


def get_guest_usage_count(user_id: int) -> int:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT count FROM guest_usage_log WHERE user_id = %s AND usage_date = %s;", (user_id, today))
            row = cursor.fetchone()
            return row[0] if row else 0
    finally:
        release_db_connection(conn)


def increment_guest_usage(user_id: int) -> None:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO guest_usage_log (user_id, usage_date, count)
                VALUES (%s, %s, 1)
                ON CONFLICT(user_id, usage_date) DO UPDATE SET count = guest_usage_log.count + 1;
                """,
                (user_id, today),
            )
            conn.commit()
    finally:
        release_db_connection(conn)


def check_guest_credit_allowed(user_id: int) -> tuple[bool, str]:
    used_today = get_guest_usage_count(user_id)
    if used_today >= GUEST_DAILY_CREDITS:
        return False, (
            f"🚫 You've used today's {GUEST_DAILY_CREDITS} guest credits. "
            "DM the bot directly or add it to your group for full access."
        )
    increment_guest_usage(user_id)
    return True, ""


def save_record(user_id: int, chat_id: int, saved_by_name: str, title: str, details: str, generated_key: str | None = None) -> str:
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    encrypted_details = encrypt_value(details)
    encrypted_key = encrypt_value(generated_key) if generated_key else None
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO saved_keys
                    (user_id, chat_id, saved_by_name, title, details, generated_key, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(user_id, chat_id, title) DO UPDATE SET
                    saved_by_name = EXCLUDED.saved_by_name,
                    details = EXCLUDED.details,
                    generated_key = EXCLUDED.generated_key,
                    created_at = EXCLUDED.created_at;
                """,
                (user_id, chat_id, saved_by_name, title, encrypted_details, encrypted_key, created_at),
            )
            conn.commit()
            return created_at
    finally:
        release_db_connection(conn)


def tag_generated_key(chat_id: int, message_id: int, key_value: str) -> None:
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    encrypted_key = encrypt_value(key_value)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO generated_keys (chat_id, message_id, key_value, created_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT(chat_id, message_id) DO UPDATE SET
                    key_value = EXCLUDED.key_value,
                    created_at = EXCLUDED.created_at;
                """,
                (chat_id, message_id, encrypted_key, created_at),
            )
            conn.commit()
    finally:
        release_db_connection(conn)


def get_tagged_key(chat_id: int, message_id: int) -> str | None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT key_value FROM generated_keys WHERE chat_id = %s AND message_id = %s;", (chat_id, message_id))
            row = cursor.fetchone()
            return decrypt_value(row[0]) if row else None
    finally:
        release_db_connection(conn)


def find_record(user_id: int, chat_id: int, title: str, team_mode: bool = False):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if team_mode:
                cursor.execute(
                    "SELECT details, generated_key, created_at, saved_by_name FROM saved_keys WHERE chat_id = %s AND title = %s;",
                    (chat_id, title),
                )
            else:
                cursor.execute(
                    "SELECT details, generated_key, created_at, saved_by_name FROM saved_keys WHERE user_id = %s AND chat_id = %s AND title = %s;",
                    (user_id, chat_id, title),
                )
            row = cursor.fetchone()
            if not row:
                return None
            details, generated_key, created_at, saved_by_name = row
            return decrypt_value(details), decrypt_value(generated_key) if generated_key else None, created_at, saved_by_name
    finally:
        release_db_connection(conn)


def delete_record(user_id: int, chat_id: int, title: str) -> bool:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM saved_keys WHERE user_id = %s AND chat_id = %s AND title = %s;", (user_id, chat_id, title))
            conn.commit()
            return cursor.rowcount > 0
    finally:
        release_db_connection(conn)


def delete_all_records(user_id: int) -> int:
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM saved_keys WHERE user_id = %s;", (user_id,))
            conn.commit()
            return cursor.rowcount
    finally:
        release_db_connection(conn)


def find_all_records(user_id: int, chat_id: int):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT title, details, generated_key, created_at, saved_by_name FROM saved_keys WHERE user_id = %s AND chat_id = %s ORDER BY created_at;",
                (user_id, chat_id),
            )
            rows = cursor.fetchall()
        return [(t, decrypt_value(d), decrypt_value(k) if k else None, ca, sbn) for t, d, k, ca, sbn in rows]
    finally:
        release_db_connection(conn)


def find_all_team_records(chat_id: int):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT title, details, generated_key, created_at, saved_by_name FROM saved_keys WHERE chat_id = %s ORDER BY created_at;",
                (chat_id,),
            )
            rows = cursor.fetchall()
        return [(t, decrypt_value(d), decrypt_value(k) if k else None, ca, sbn) for t, d, k, ca, sbn in rows]
    finally:
        release_db_connection(conn)


def get_or_create_user(user_id: int) -> dict:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT user_id, trial_start, subscription_expires FROM users WHERE user_id = %s;", (user_id,))
            row = cursor.fetchone()
            if row:
                return {"user_id": row[0], "trial_start": row[1], "subscription_expires": row[2]}

            cursor.execute("INSERT INTO users (user_id, trial_start, subscription_expires) VALUES (%s, %s, NULL);", (user_id, today))
            conn.commit()
            return {"user_id": user_id, "trial_start": today, "subscription_expires": None}
    finally:
        release_db_connection(conn)


def is_subscribed(user_row: dict) -> bool:
    expires = user_row.get("subscription_expires")
    if not expires:
        return False
    try:
        expires_dt = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
        return datetime.utcnow() < expires_dt
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
            current_expiry = None

    base = current_expiry if current_expiry and current_expiry > now else now
    new_expiry_str = (base + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET subscription_expires = %s WHERE user_id = %s;", (new_expiry_str, user_id))
            conn.commit()
        return new_expiry_str
    finally:
        release_db_connection(conn)


def get_today_credit_usage(user_id: int) -> int:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT count FROM usage_log WHERE user_id = %s AND usage_date = %s;", (user_id, today))
            row = cursor.fetchone()
            return row[0] if row else 0
    finally:
        release_db_connection(conn)


def increment_credit_usage(user_id: int) -> None:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO usage_log (user_id, usage_date, count)
                VALUES (%s, %s, 1)
                ON CONFLICT(user_id, usage_date) DO UPDATE SET count = usage_log.count + 1;
                """,
                (user_id, today),
            )
            conn.commit()
    finally:
        release_db_connection(conn)


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
    keyboard = [[InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]]
    sent_message = await update.message.reply_text(
        f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard)
    )
    tag_generated_key(sent_message.chat_id, sent_message.message_id, key)


@rate_limit
@credit_limit
async def generate_alphanumeric(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Generate and send an alphanumeric key with regenerate button"""
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
    """Full command reference shown when the 'Commands' button on /start is tapped."""
    return (
        "Available Commands:\n"
        "/numeric - Generate a numeric 8-digit key\n"
        "/alphanumeric - Generate an alphanumeric 8-digit key\n"
        "/save {title} {details} - Save a key (must reply to a generated key message)\n"
        "/find {title} - Retrieve a saved key by title\n"
        "/delete {title} - Delete a saved entry by title\n"
        "/delete_all_my_data - Delete ALL your saved entries\n"
        "/export_my_data - Export saved data for THIS chat only (your own in DMs; the whole "
        "team's if sharing is on in a group)\n"
        "/status - Check your trial/subscription status and remaining credits\n"
        "/subscribe - Get unlimited credits for 30 days\n"
        "/team_sharing on|off - Toggle team key sharing for this group (group chats only)\n"
        "/help - Contact support, collaboration or sponsorship\n\n"
        "Example usage:\n"
        "/numeric - Gets a key like: 47392615\n"
        "/alphanumeric - Gets a key like: K9M2L7X4\n"
        "[Reply to a generated key message] /save api1 my-api-key - attaches the generated key to your saved note.\n"
        "/find api1 - Retrieve the saved key for title 'api1'.\n"
        "/delete api1 - Delete the saved entry for title 'api1'.\n\n"
        "🆓 Free users get 10 credits/day for your first 7 days.\n"
        "💫 Subscribers get unlimited credits for 30 days.\n"
        "Only /numeric, /alphanumeric, and Regenerate spend credits — everything else is free.\n\n"
        "🔒 Your data is encrypted at rest and only accessible via your own Telegram account. "
        "DM-saved entries never appear in group exports or group /find, and vice versa — "
        "each chat is its own partition."
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
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
            "⚠️ /save must be used as a reply to a generated key message.\n"
            "Reply directly to a /numeric, /alphanumeric, or regenerated key message with /save."
        )
        return

    replied = update.message.reply_to_message
    chat_id = update.effective_chat.id
    generated_key = get_tagged_key(chat_id, replied.message_id)
    if generated_key is None:
        await update.message.reply_text(
            "⚠️ That message isn't a key this bot generated, so I can't save it.\n"
            "Reply directly to a /numeric, /alphanumeric, or regenerated key message with /save."
        )
        return

    user_id = update.effective_user.id
    saved_by_name = update.effective_user.full_name or (
        f"@{update.effective_user.username}" if update.effective_user.username else "Unknown"
    )
    created_at = save_record(user_id, chat_id, saved_by_name, title, details, generated_key)

    key_line = f"\n🔑 Generated Key: {generated_key}" if generated_key else ""
    await update.message.reply_text(
        f"Saved '{title}'.\nDetails: {details}{key_line}\nCreated: {created_at}"
    )


def build_find_response(
    title: str, details: str, generated_key: str | None, created_at: str,
    saved_by_name: str | None = None,
) -> str:
    """Build a /find response (HTML-formatted) with the generated key in a tap-to-copy <code> block.
    All user-supplied text is HTML-escaped so characters like _ * [ ` in titles/details can never
    break message parsing. saved_by_name is only shown for team-shared results."""
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
    if not title:
        await update.message.reply_text("Please provide a title to look up.\nUsage: /find {title}")
        return

    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    chat_type = update.effective_chat.type
    team_mode = chat_type in ("group", "supergroup") and is_sharing_enabled(chat_id)

    try:
        record = find_record(user_id, chat_id, title, team_mode=team_mode)
    except InvalidToken:
        await update.message.reply_text(
            "⚠️ That entry couldn't be decrypted (it was saved with a different encryption key)."
        )
        return
    if not record:
        if team_mode:
            await update.message.reply_text(
                f"No saved entry found for title '{title}' among this team's shared keys."
            )
        else:
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
    """Export saved entries. Scoped to the chat the command is run in — a DM export never
    includes group-saved entries and a group export never includes DM or other-group entries.
    In a group with team sharing ON, exports every teammate's entries saved in that group
    (with who saved each one); otherwise exports only the caller's own entries for this chat.
    Free to use — export doesn't spend credits."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    chat_type = update.effective_chat.type
    team_mode = chat_type in ("group", "supergroup") and is_sharing_enabled(chat_id)

    try:
        if team_mode:
            records = find_all_team_records(chat_id)
            scope_label = "this group's shared"
            header = "📦 This group's shared saved data:\n"
        else:
            records = find_all_records(user_id, chat_id)
            scope_label = "your"
            header = "📦 Your saved data for this chat:\n"
    except InvalidToken:
        await update.message.reply_text(
            "⚠️ Some entries couldn't be decrypted (saved with a different encryption key)."
        )
        return

    if not records:
        await update.message.reply_text(f"There's no {scope_label} saved data to export here.")
        return

    lines = [header]
    for title, details, generated_key, created_at, saved_by_name in records:
        key_text = generated_key if generated_key else "N/A"
        saved_by_line = f"Saved by: {saved_by_name}\n" if team_mode else ""
        lines.append(
            f"Title: {title}\n{saved_by_line}Details: {details}\nGenerated key: {key_text}\nSaved: {created_at}\n"
        )

    export_text = "\n".join(lines)

    # Telegram messages cap at ~4096 characters; chunk if needed
    max_len = 3500
    if len(export_text) <= max_len:
        await update.message.reply_text(export_text)
    else:
        chunk = ""
        for line_block in lines:
            if len(chunk) + len(line_block) > max_len:
                await update.message.reply_text(chunk)
                chunk = ""
            chunk += line_block + "\n"
        if chunk:
            await update.message.reply_text(chunk)


@rate_limit
async def team_sharing_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Toggle or check team key-sharing for the current group. Group chats only; any member may toggle it."""
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
            "When ON, any member can /find keys saved by teammates in this group, "
            "and will see who saved them. /delete and /export_my_data always stay personal.\n\n"
            "Use /team_sharing on or /team_sharing off to change it."
        )
        return

    enabled = args[0].lower() == "on"
    set_sharing_enabled(chat.id, enabled)
    if enabled:
        await update.message.reply_text(
            "✅ Team sharing is now ON for this group.\n"
            "Any member can now /find keys saved by teammates here, and will see who saved them."
        )
    else:
        await update.message.reply_text(
            "❌ Team sharing is now OFF for this group.\n"
            "/find will only show your own saved keys again."
        )


@rate_limit
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show the user their current trial/subscription status and remaining daily credits."""
    user_id = update.effective_user.id
    user_row = get_or_create_user(user_id)

    if is_subscribed(user_row):
        await update.message.reply_text(
            f"✅ Active subscription — unlimited credits until {user_row['subscription_expires']} UTC."
        )
        return

    trial_start = datetime.strptime(user_row["trial_start"], "%Y-%m-%d")
    days_elapsed = (datetime.utcnow() - trial_start).days
    days_left = max(0, TRIAL_PERIOD_DAYS - days_elapsed)

    if days_left == 0:
        await update.message.reply_text(
            "🚫 Your free trial has ended.\nSubscribe with /subscribe for 30 days of unlimited credits."
        )
        return

    used_today = get_today_credit_usage(user_id)
    remaining_today = max(0, FREE_DAILY_CREDITS - used_today)
    await update.message.reply_text(
        f"🆓 Free trial: {days_left} day(s) left.\n"
        f"Credits used today: {used_today}/{FREE_DAILY_CREDITS}\n"
        f"Credits remaining today: {remaining_today}\n\n"
        f"Only /numeric, /alphanumeric, and Regenerate spend credits.\n"
        f"Subscribe with /subscribe for 30 days of unlimited credits."
    )


@rate_limit
async def subscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a Telegram Stars invoice for the 30-day subscription."""
    chat_id = update.effective_chat.id
    await context.bot.send_invoice(
        chat_id=chat_id,
        title="AuthKeys Bot — 30 Day Subscription",
        description=f"Unlimited credits on AuthKeys Bot for {SUBSCRIPTION_DAYS} days.",
        payload=f"subscription_{update.effective_user.id}",
        provider_token="",  # empty string is required for Telegram Stars payments
        currency="XTR",
        prices=[LabeledPrice("30-day subscription", SUBSCRIPTION_PRICE_STARS)],
    )


async def precheckout_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Confirm the pre-checkout query so Telegram can proceed with the payment."""
    query = update.pre_checkout_query
    if query.invoice_payload.startswith("subscription_"):
        await query.answer(ok=True)
    else:
        await query.answer(ok=False, error_message="Something went wrong with your order.")


async def successful_payment_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Grant the subscription once Telegram confirms the Stars payment succeeded."""
    user_id = update.effective_user.id
    new_expiry = grant_subscription(user_id, days=SUBSCRIPTION_DAYS)
    await update.message.reply_text(
        f"✅ Payment received! You now have unlimited credits until {new_expiry} UTC."
    )


def _rate_limit_wait_seconds(user_id: int) -> float | None:
    """Check + record rate limit for a user without needing update.message (used by button callbacks).
    Returns seconds left to wait if still limited, otherwise None (and records this attempt as the new 'last time')."""
    now = time.monotonic()
    last_time = _last_command_time.get(user_id, 0)
    if now - last_time < RATE_LIMIT_SECONDS:
        return round(RATE_LIMIT_SECONDS - (now - last_time), 1)
    _last_command_time[user_id] = now
    return None


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle callback queries from inline keyboards"""
    query = update.callback_query
    user_id = query.from_user.id

    # The "Regenerate" button generates a new key just like /numeric or /alphanumeric,
    # so it spends a credit too — otherwise a free user could tap Regenerate unlimited
    # times to bypass the daily credit cap.
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
        keyboard = [
            [InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup
        )
        tag_generated_key(query.message.chat_id, query.message.message_id, key)

    elif query.data == "regenerate_alphanumeric":
        key = generate_alphanumeric_key()
        keyboard = [
            [
                InlineKeyboardButton(
                    "🔄 Regenerate", callback_data="regenerate_alphanumeric"
                )
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"🔑 Alphanumeric Key: `{key}`",
            parse_mode="Markdown",
            reply_markup=reply_markup,
        )
        tag_generated_key(query.message.chat_id, query.message.message_id, key)

    elif query.data == "confirm_delete_all":
        user_id = query.from_user.id
        count = delete_all_records(user_id)
        await query.edit_message_text(f"✅ Deleted {count} saved entr{'y' if count == 1 else 'ies'}.")

    elif query.data == "cancel_delete_all":
        await query.edit_message_text("Cancelled. Your data was not deleted.")

    elif query.data == "show_all_commands":
        back_keyboard = InlineKeyboardMarkup(
            [[InlineKeyboardButton("⬅️ Back", callback_data="back_to_welcome")]]
        )
        await query.edit_message_text(full_commands_text(), reply_markup=back_keyboard)

    elif query.data == "back_to_welcome":
        await query.edit_message_text(
            build_welcome_message(), parse_mode="MarkdownV2", reply_markup=build_welcome_keyboard()
        )


async def handle_guest_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle @mentions of the bot in chats it isn't a member of (Telegram Guest Mode, May 2026).
    Registered as a TypeHandler on every raw Update in a separate handler group, so it doesn't
    interfere with normal command routing — it no-ops instantly for any update that isn't a guest mention.

    NOTE: answer_guest_query()'s exact result schema is thinly documented as of this writing (the
    feature is ~2 months old). This implementation follows the Bot API changelog's statement that
    guest query results reuse the same InputMessageContent pattern as inline query results — test
    against your live bot before relying on it in production.
    """
    guest_msg = getattr(update, "guest_message", None)
    if guest_msg is None:
        return  # not a guest mention — let the normal handlers deal with this update

    caller_user = getattr(guest_msg, "guest_bot_caller_user", None)
    if caller_user is None:
        return
    user_id = caller_user.id

    text = (guest_msg.text or "").lower()
    if "alphanumeric" in text:
        key_type, key = "Alphanumeric", generate_alphanumeric_key()
    elif "numeric" in text:
        key_type, key = "Numeric", generate_numeric_key()
    else:
        # Per design: only reply when a key type is explicitly requested in the mention.
        return

    allowed, reason = check_guest_credit_allowed(user_id)
    if not allowed:
        result = InlineQueryResultArticle(
            id=str(uuid.uuid4()),
            title="Daily guest credits reached",
            input_message_content=InputTextMessageContent(reason),
        )
        await context.bot.answer_guest_query(guest_query_id=guest_msg.guest_query_id, result=result)
        return

    result = InlineQueryResultArticle(
        id=str(uuid.uuid4()),
        title=f"{key_type} Key",
        input_message_content=InputTextMessageContent(f"🔑 {key_type} Key: {key}"),
    )
    await context.bot.answer_guest_query(guest_query_id=guest_msg.guest_query_id, result=result)


def main() -> None:
    """Start the bot."""
    if not TOKEN:
        raise ValueError("TELEGRAM_TOKEN not found in environment variables!")

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
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(PreCheckoutQueryHandler(precheckout_callback))
    application.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment_callback))
    # Separate handler group (not 0) so this runs alongside normal command routing instead of
    # intercepting every update — it no-ops immediately unless update.guest_message is present.
    application.add_handler(TypeHandler(Update, handle_guest_message), group=1)

    init_db()

    if WEBHOOK_URL:
        webhook_path = WEBHOOK_PATH.lstrip("/")
        webhook_url = WEBHOOK_URL.rstrip("/")
        if webhook_path:
            webhook_url = f"{webhook_url}/{webhook_path}"

        application.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=webhook_path,
            webhook_url=webhook_url,
        )
    else:
        application.run_polling()


if __name__ == "__main__":
    main()
