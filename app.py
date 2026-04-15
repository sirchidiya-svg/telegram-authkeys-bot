import os
import random
import string
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

# Load environment variables
load_dotenv()
TOKEN = os.getenv("TELEGRAM_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
WEBHOOK_PATH = os.getenv("WEBHOOK_PATH", "webhook")
PORT = int(os.getenv("PORT", "8443"))


def generate_numeric_key(length=8):
    """Generate a numeric key of specified length"""
    return "".join(random.choices(string.digits, k=length))


def generate_alphanumeric_key(length=8):
    """Generate an alphanumeric key of specified length"""
    characters = string.ascii_uppercase + string.digits
    return "".join(random.choices(characters, k=length))


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    welcome_message = """
Welcome to AuthKeys Generator Bot! 🤖

Available Commands:
/numeric - Generate a numeric 8-digit key
/alphanumeric - Generate an alphanumeric 8-digit key
/help - Show this message

Example usage:
/numeric - Gets a key like: 47392615
/alphanumeric - Gets a key like: K9M2L7X4
"""
    await update.message.reply_text(welcome_message)


async def generate_numeric(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Generate and send a numeric key with regenerate button"""
    key = generate_numeric_key()

    # Create inline keyboard with regenerate button
    keyboard = [
        [InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup
    )


async def generate_alphanumeric(
    update: Update, context: ContextTypes.DEFAULT_TYPE
) -> None:
    """Generate and send an alphanumeric key with regenerate button"""
    key = generate_alphanumeric_key()

    # Create inline keyboard with regenerate button
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

Example usage:
/numeric - Gets a key like: 47392615
/alphanumeric - Gets a key like: K9M2L7X4
"""
    await update.message.reply_text(help_message)


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle callback queries from inline keyboards"""
    query = update.callback_query
    await query.answer()

    if query.data == "regenerate_numeric":
        key = generate_numeric_key()
        # Create inline keyboard with regenerate button
        keyboard = [
            [InlineKeyboardButton("🔄 Regenerate", callback_data="regenerate_numeric")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await query.edit_message_text(
            f"🔑 Numeric Key: `{key}`", parse_mode="Markdown", reply_markup=reply_markup
        )

    elif query.data == "regenerate_alphanumeric":
        key = generate_alphanumeric_key()
        # Create inline keyboard with regenerate button
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


def main() -> None:
    """Start the bot."""
    if not TOKEN:
        raise ValueError("TELEGRAM_TOKEN not found in environment variables!")

    # Create the Application
    application = Application.builder().token(TOKEN).build()

    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("numeric", generate_numeric))
    application.add_handler(CommandHandler("alphanumeric", generate_alphanumeric))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(handle_callback))

    # Run the bot using webhook if the URL is configured, otherwise use polling.
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
