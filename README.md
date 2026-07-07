# AuthKeys Telegram Bot

A Telegram bot that generates keys and lets users save them with titles and details.

## Features

- `/numeric` - generate an 8-digit numeric key
- `/alphanumeric` - generate an 8-character alphanumeric key
- `/save {title} {details}` - save a key with a title and details
- `/find {title}` - retrieve the saved title, details, generated key, and timestamp
- `.env` support for `TELEGRAM_TOKEN`
- SQLite persistence in `authkeys.db`

## How it works

- Use `/numeric` or `/alphanumeric` to generate a key.
- Reply to the generated key message and send `/save {title} {details}`.
- The bot extracts the generated key from the replied message and stores it along with the user-provided details.
- Use `/find {title}` to retrieve:
  - title
  - details
  - generated key
  - saved timestamp

## Setup

1. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
2. Create a `.env` file in the project folder with:
   ```ini
   TELEGRAM_TOKEN=your_bot_token
   ```
3. Run the bot:
   ```bash
   python app.py
   ```

## Notes

- The bot uses polling when `WEBHOOK_URL` is not set.
- The SQLite file `authkeys.db` is created automatically.
- `authkeys.db` is ignored from git to avoid committing database contents.
