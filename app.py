import os
import random
import sqlite3
import string
import time
from datetime import datetime
from functools import wraps
import asyncio
import sys
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

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

Example usage:
/numeric - Gets a key like: 47392615
/alphanumeric - Gets a key like: K9M2L7X4
[Reply to a generated key message] /save api1 my-api-key - The bot will extract the generated key and store it with your details.
/find api1 - Retrieve the saved key for title 'api1'.
/delete api1 - Delete the saved entry for title 'api1'.

🔒 Your data is encrypted at rest and only accessible via your own Telegram account.
"""
    await update.message.reply_text(welcome_message)


@rate_limit
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


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle callback queries from inline keyboards"""
    query = update.callback_query
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
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(handle_callback))

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
