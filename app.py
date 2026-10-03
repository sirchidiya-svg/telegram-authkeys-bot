import os
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
from cryptography.fernet import Fernet
import psycopg2
from psycopg2 import pool
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
db_pool = psycopg2.pool.SimpleConnectionPool(minconn=1, maxconn=10, dsn=DATABASE_URL)


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
    tag_
