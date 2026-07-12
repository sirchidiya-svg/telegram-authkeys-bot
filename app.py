import os
import random
import sqlite3
import string
import time
from datetime import datetime, timedelta
from functools import wraps
import asyncio
import sys
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton, LabeledPrice
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    PreCheckoutQueryHandler,
    MessageHandler,
    filters,
)

# Load environment variables
load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "webhook")
PORT = int(os.getenv("PORT", "8443"))
DB_PATH = os.path.join(os.path.dirname(__file__), "authkeys.db")

# --- Encryption setup ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY not found in environment variables!")
FERNET = Fernet(ENCRYPTION_KEY.encode())


def encrypt_value(value: str) -> str:
    return FERNET.encrypt(value.encode()).decode()


def decrypt_value(value: str) -> str:
    return FERNET.decrypt(value.encode()).decode()


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


# --- Usage plan setup (free trial + subscription) ---
FREE_DAILY_LIMIT = 10       # free users get this many uses per day
TRIAL_PERIOD_DAYS = 7       # free tier lasts this many days from first use
SUBSCRIPTION_DAYS = 30      # a paid subscription grants unlimited use for this many days
SUBSCRIPTION_PRICE_STARS = int(os.getenv("SUBSCRIPTION_PRICE_STARS", "100"))  # price in Telegram Stars


def generate_numeric_key(length=8):
    """Generate a numeric key of specified length"""
    return "".join(random.choices(string.digits, k=length))


def generate_alphanumeric_key(length=8):
    """Generate an alphanumeric key of specified length"""
    characters = string.ascii_uppercase + string.digits
    return "".join(random.choices(characters, k=length))


def init_db() -> None:
    """Initialize the SQLite database and saved_keys table."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_keys (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                generated_key TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(user_id, title)
            )
            """
        )
        cursor = conn.execute("PRAGMA table_info(saved_keys)")
        columns = {row[1] for row in cursor.fetchall()}
        if "generated_key" not in columns:
            conn.execute("ALTER TABLE saved_keys ADD COLUMN generated_key TEXT")

        # --- Usage plan tables ---
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                trial_start TEXT NOT NULL,
                subscription_expires TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_log (
                user_id INTEGER NOT NULL,
                usage_date TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, usage_date)
            )
            """
        )


def save_record(user_id: int, title: str, details: str, generated_key: str | None = None) -> str:
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    encrypted_details = encrypt_value(details)
    encrypted_key = encrypt_value(generated_key) if generated_key else None
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO saved_keys (user_id, title, details, generated_key, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, title, encrypted_details, encrypted_key, created_at),
        )
    return created_at


def find_record(user_id: int, title: str):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT details, generated_key, created_at FROM saved_keys WHERE user_id = ? AND title = ?",
            (user_id, title),
        )
        row = cursor.fetchone()
        if not row:
            return None
        details, generated_key, created_at = row
        decrypted_details = decrypt_value(details)
        decrypted_key = decrypt_value(generated_key) if generated_key else None
        return decrypted_details, decrypted_key, created_at


def delete_record(user_id: int, title: str) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM saved_keys WHERE user_id = ? AND title = ?",
            (user_id, title),
        )
        return cursor.rowcount > 0


def delete_all_records(user_id: int) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "DELETE FROM saved_keys WHERE user_id = ?",
            (user_id,),
        )
        return cursor.rowcount


def find_all_records(user_id: int):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT title, details, generated_key, created_at FROM saved_keys WHERE user_id = ? ORDER BY created_at",
            (user_id,),
        )
        rows = cursor.fetchall()

    decrypted_rows = []
    for title, details, generated_key, created_at in rows:
        decrypted_details = decrypt_value(details)
        decrypted_key = decrypt_value(generated_key) if generated_key else None
        decrypted_rows.append((title, decrypted_details, decrypted_key, created_at))
    return decrypted_rows


# --- Usage plan helpers ---

def get_or_create_user(user_id: int) -> dict:
    """Fetch a user's plan row, creating one (and starting their trial) on first use."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT user_id, trial_start, subscription_expires FROM users WHERE user_id = ?",
            (user_id,),
        )
        row = cursor.fetchone()
        if row:
            return {"user_id": row[0], "trial_start": row[1], "subscription_expires": row[2]}

        conn.execute(
            "INSERT INTO users (user_id, trial_start, subscription_expires) VALUES (?, ?, NULL)",
            (user_id, today),
        )
        return {"user_id": user_id, "trial_start": today, "subscription_expires": None}


def is_subscribed(user_row: dict) -> bool:
    """Return True if the user currently has an active (unexpired) subscription."""
    expires = user_row.get("subscription_expires")
    if not expires:
        return False
    try:
        expires_dt = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    return datetime.utcnow() < expires_dt


def grant_subscription(user_id: int, days: int = SUBSCRIPTION_DAYS) -> str:
    """Activate (or extend) a user's subscription. Returns the new expiry timestamp string.

    Hook this up to your Telegram Stars payment handler once that's wired in.
    """
    user_row = get_or_create_user(user_id)
    now = datetime.utcnow()

    current_expiry = None
    if user_row["subscription_expires"]:
        try:
            current_expiry = datetime.strptime(user_row["subscription_expires"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            current_expiry = None

    # Extend from current expiry if still active, otherwise start fresh from now
    base = current_expiry if current_expiry and current_expiry > now else now
    new_expiry = base + timedelta(days=days)
    new_expiry_str = new_expiry.strftime("%Y-%m-%d %H:%M:%S")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET subscription_expires = ? WHERE user_id = ?",
            (new_expiry_str, user_id),
        )
    return new_expiry_str


def get_today_usage_count(user_id: int) -> int:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            "SELECT count FROM usage_log WHERE user_id = ? AND usage_date = ?",
            (user_id, today),
        )
        row = cursor.fetchone()
        return row[0] if row else 0


def increment_usage(user_id: int) -> None:
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO usage_log (user_id, usage_date, count) VALUES (?, ?, 1)
            ON CONFLICT(user_id, usage_date) DO UPDATE SET count = count + 1
            """,
            (user_id, today),
        )


def check_usage_allowed(user_id: int) -> tuple[bool, str]:
    """Core plan-enforcement check.

    - Active subscribers: unlimited use (for SUBSCRIPTION_DAYS from activation/extension).
    - Free users: FREE_DAILY_LIMIT uses/day, only during the first TRIAL_PERIOD_DAYS days
      since their first-ever use. After that, they must subscribe.
    Returns (allowed, message_if_blocked).
    """
    user_row = get_or_create_user(user_id)

    if is_subscribed(user_row):
        increment_usage(user_id)  # tracked for stats only, doesn't block
        return True, ""

    trial_start = datetime.strptime(user_row["trial_start"], "%Y-%m-%d")
    days_elapsed = (datetime.utcnow() - trial_start).days

    if days_elapsed >= TRIAL_PERIOD_DAYS:
        return False, (
            "🚫 Your 7-day free trial has ended.\n"
            "Subscribe to unlock 30 days of unlimited use — see /subscribe."
        )

    today_count = get_today_usage_count(user_id)
    if today_count >= FREE_DAILY_LIMIT:
        return False, (
            f"🚫 You've hit today's free limit of {FREE_DAILY_LIMIT} uses.\n"
            f"Come back tomorrow, or subscribe for unlimited access — see /subscribe."
        )

    increment_usage(user_id)
    return True, ""


def usage_limit(func):
    """Decorator that enforces the free-trial / subscription usage plan before running a command."""
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        allowed, reason = check_usage_allowed(user_id)
        if not allowed:
            await update.message.reply_text(reason)
            return
        return await func(update, context)
    return wrapper


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    welcome_message = """
Welcome to AuthKeys Generator Bot! 🤖

Available Commands:
/numeric - Generate a numeric 8-digit key
/alphanumeric - Generate an alphanumeric 8-digit key
/help - Show this message

/save {title} {details} - Save a key with a title and details
/find {title} - Retrieve a saved key by title
/delete {title} - Delete a saved entry by title
/delete_all_my_data - Delete ALL your saved entries
/export_my_data - Export all your saved data
/status - Check your trial/subscription status and remaining uses
/subscribe - Get unlimited use for 30 days

Example usage:
/numeric - Gets a key like: 47392615
/alphanumeric - Gets a key like: K9M2L7X4
[Reply to a generated key message] /save api1 my-api-key - The bot will extract the generated key and store it with your details.
/find api1 - Retrieve the saved key for title 'api1'.
/delete api1 - Delete the saved entry for title 'api1'.

🆓 Free users get 10 uses/day for your first 7 days.
💫 Subscribers get unlimited use for 30 days.

🔒 Your data is encrypted at rest and only accessible via your own Telegram account.
"""
    await update.message.reply_text(welcome_message)


@rate_limit
@usage_limit
async def generate_numeric(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Generate and send a numeric key with regenerate button"""
    key = generate_numeric_key()

    keyboard = [
        [InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup
    )


@rate_limit
@usage_limit
async def generate_alphanumeric(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Generate and send an alphanumeric key with regenerate button"""
    key = generate_alphanumeric_key()

    keyboard = [
        [InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_alphanumeric")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"🔑 Alphanumeric Key: `{key}`",
        parse_mode="Markdown",
        reply_markup=reply_markup,
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    help_message = """
Available Commands:
/numeric - Generate a numeric 8-digit key
/alphanumeric - Generate an alphanumeric 8-digit key
/help - Show this message

/save {title} {details} - Save a key with a title and details
/find {title} - Retrieve a saved key by title
/delete {title} - Delete a saved entry by title
/delete_all_my_data - Delete ALL your saved entries
/export_my_data - Export all your saved data
/status - Check your trial/subscription status and remaining uses
/subscribe - Get unlimited use for 30 days

Example usage:
/numeric - Gets a key like: 47392615
/alphanumeric - Gets a key like: K9M2L7X4
[Reply to a generated key message] /save api1 my-api-key - The bot will extract the generated key and store it with your details.
/find api1 - Retrieve the saved key for title 'api1'.
/delete api1 - Delete the saved entry for title 'api1'.
"""
    await update.message.reply_text(help_message)


def extract_details_from_message(message):
    """Extract the saved value from a replied-to message."""
    if not message:
        return None
    source = message.text or message.caption or ""
    if not source:
        return None

    # Try to extract between backticks (markdown code formatting)
    if "`" in source:
        parts = source.split("`")
        if len(parts) >= 3:
            extracted = parts[1].strip()
            if extracted:
                return extracted

    # Fallback: try to extract the last word/token that looks like a key
    tokens = source.split()
    if tokens:
        for token in reversed(tokens):
            token = token.strip()
            if token and all(c.isalnum() or c in '-_' for c in token) and len(token) >= 4:
                return token

    result = source.strip()
    return result if result else None


@rate_limit
@usage_limit
async def save_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    parts = text.split(" ", 2)

    if len(parts) < 3 or not parts[1].strip() or not parts[2].strip():
        await update.message.reply_text(
            "Usage: /save {title} {details}\nExample: /save api1 my-important-key"
        )
        return

    title = parts[1].strip()
    details = parts[2].strip()
    generated_key = None

    if update.message.reply_to_message:
        generated_key = extract_details_from_message(update.message.reply_to_message)

    user_id = update.effective_user.id
    created_at = save_record(user_id, title, details, generated_key)

    key_line = f"\n🔑 Generated Key: {generated_key}" if generated_key else ""
    await update.message.reply_text(
        f"Saved '{title}'.\nDetails: {details}{key_line}\nCreated: {created_at}"
    )


def build_find_response(title: str, details: str, generated_key: str | None, created_at: str) -> str:
    """Build a /find response with the generated key formatted for easy copying."""
    generated_key_text = generated_key if generated_key else "N/A"
    return (
        f"Title: {title}\n"
        f"Details: {details}\n"
        f"Generated key: `{generated_key_text}`\n"
        f"Saved: {created_at}"
    )


@rate_limit
@usage_limit
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
    record = find_record(user_id, title)
    if not record:
        await update.message.reply_text(f"No saved entry found for title '{title}'.")
        return

    details, generated_key, created_at = record
    response = build_find_response(title, details, generated_key, created_at)
    await update.message.reply_text(response, parse_mode="Markdown")


@rate_limit
@usage_limit
async def delete_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if not args:
        await update.message.reply_text("Usage: /delete {title}\nExample: /delete api1")
        return

    title = args[0].strip()
    user_id = update.effective_user.id
    deleted = delete_record(user_id, title)

    if deleted:
        await update.message.reply_text(f"Deleted '{title}'.")
    else:
        await update.message.reply_text(f"No saved entry found for title '{title}'.")


@rate_limit
@usage_limit
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
@usage_limit
async def export_my_data_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    records = find_all_records(user_id)

    if not records:
        await update.message.reply_text("You have no saved data to export.")
        return

    lines = ["📦 Your saved data:\n"]
    for title, details, generated_key, created_at in records:
        key_text = generated_key if generated_key else "N/A"
        lines.append(
            f"Title: {title}\nDetails: {details}\nGenerated key: {key_text}\nSaved: {created_at}\n"
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
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show the user their current trial/subscription status and remaining daily uses."""
    user_id = update.effective_user.id
    user_row = get_or_create_user(user_id)

    if is_subscribed(user_row):
        await update.message.reply_text(
            f"✅ Active subscription — unlimited use until {user_row['subscription_expires']} UTC."
        )
        return

    trial_start = datetime.strptime(user_row["trial_start"], "%Y-%m-%d")
    days_elapsed = (datetime.utcnow() - trial_start).days
    days_left = max(0, TRIAL_PERIOD_DAYS - days_elapsed)

    if days_left == 0:
        await update.message.reply_text(
            "🚫 Your free trial has ended.\nSubscribe with /subscribe for 30 days of unlimited use."
        )
        return

    used_today = get_today_usage_count(user_id)
    remaining_today = max(0, FREE_DAILY_LIMIT - used_today)
    await update.message.reply_text(
        f"🆓 Free trial: {days_left} day(s) left.\n"
        f"Today's usage: {used_today}/{FREE_DAILY_LIMIT}\n"
        f"Remaining today: {remaining_today}\n\n"
        f"Subscribe with /subscribe for 30 days of unlimited use."
    )


@rate_limit
async def subscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a Telegram Stars invoice for the 30-day subscription."""
    chat_id = update.effective_chat.id
    await context.bot.send_invoice(
        chat_id=chat_id,
        title="AuthKeys Bot — 30 Day Subscription",
        description=f"Unlimited use of AuthKeys Bot for {SUBSCRIPTION_DAYS} days.",
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
        f"✅ Payment received! You now have unlimited use until {new_expiry} UTC."
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
    # so it must be rate-limited and counted against the free daily usage limit too —
    # otherwise a free user could tap Regenerate unlimited times to bypass the cap.
    if query.data in ("regenerate_numeric", "regenerate_alphanumeric"):
        wait = _rate_limit_wait_seconds(user_id)
        if wait is not None:
            await query.answer(f"⏳ Please wait {wait}s before trying again.", show_alert=True)
            return

        allowed, reason = check_usage_allowed(user_id)
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

    elif query.data == "confirm_delete_all":
        user_id = query.from_user.id
        count = delete_all_records(user_id)
        await query.edit_message_text(f"✅ Deleted {count} saved entr{'y' if count == 1 else 'ies'}.")

    elif query.data == "cancel_delete_all":
        await query.edit_message_text("Cancelled. Your data was not deleted.")


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
    application.add_handler(CommandHandler("subscribe", subscribe_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(PreCheckoutQueryHandler(precheckout_callback))
    application.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment_callback))

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
