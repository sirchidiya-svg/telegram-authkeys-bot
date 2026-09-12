# AuthKeys Telegram Bot

A Telegram bot that generates, encrypts, and manages keys entirely through chat commands — with per-group team sharing, a free-trial/subscription credit system, and a guest mode for chats the bot isn't a member of.

## Features

**Key generation**
- `/numeric` — generate an 8-digit numeric key
- `/alphanumeric` — generate an 8-character alphanumeric key (guaranteed at least one letter and one digit)
- Both come with an inline "🔄 Regenerate" button

**Saving & retrieving**
- `/save {title} {details}` — sent as a reply to a generated key message; the bot verifies the reply is a real bot-generated key, then stores it (encrypted) with your title and details
- `/find {title}` — retrieve a saved entry: title, details, key, saved timestamp (and who saved it, if it came from team sharing)
- `/delete {title}` — delete one of your own saved entries
- `/delete_all_my_data` — delete all your own saved entries (with a confirm/cancel prompt)
- `/export_my_data` — bulk export, **scoped to the current chat only** (see Team sharing & privacy below)

**Team sharing**
- `/team_sharing on|off` — toggle shared visibility for the current group (group chats only)
- When ON, any member can `/find` or `/export_my_data` keys teammates saved in that group, and sees who saved them
- `/delete` and `/delete_all_my_data` always stay personal, even with sharing on — no one can delete another member's entry

**Credits (free trial + subscription)**
- Only `/numeric`, `/alphanumeric`, and Regenerate spend credits — everything else (`/save`, `/find`, `/delete`, `/export_my_data`) is free to use as often as you like
- Free tier: 10 credits/day for your first 7 days
- `/subscribe` — pay with Telegram Stars for 30 days of unlimited credits
- `/status` — check trial days left / subscription expiry and credits remaining today

**Guest mode**
- @mention the bot in a group it hasn't been added to, and it'll reply with a numeric or alphanumeric key on request
- Separate, tighter daily cap (5/day) independent of the main credit plan

**Security & reliability**
- Fernet symmetric encryption for every stored key and detail field — nothing sensitive is written to disk in plaintext
- Per-user rate limiting (3s cooldown) on every command
- `.env` support for all configuration (see Setup)
- SQLite persistence in `authkeys.db` (auto-created, git-ignored)

## How it works

1. Use `/numeric` or `/alphanumeric` to generate a key.
2. Reply to the generated key message with `/save {title} {details}`.
3. The bot confirms the replied-to message is a key it actually generated, then encrypts and stores the key + details + a timestamp, scoped to the chat you're in.
4. Use `/find {title}` to retrieve it later — in a group with team sharing on, this also finds teammates' entries.
5. Use `/export_my_data` for a bulk dump — same chat-scoping rules apply.

## Team sharing & privacy (partitioning)

Every saved entry is tied to the `chat_id` it was saved in. A private chat (DM) with the bot and a group chat always have different `chat_id`s, so:

- Entries saved in a DM **never** appear in a group's `/find` or `/export_my_data`, even for the same user.
- Entries saved in one group **never** appear in another group, or in a DM.
- `/export_my_data` in a group with team sharing **on** exports that group's shared entries (with who saved each one); with sharing **off**, it exports only your own entries for that specific group.

This is enforced at the database query level (every lookup filters by `chat_id`), not just hidden in the UI.

## Setup

1. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
2. Create a `.env` file in the project folder with:
   ```ini
   TELEGRAM_TOKEN=your_bot_token
   ENCRYPTION_KEY=your_fernet_key
   ```
   Generate a Fernet key with:
   ```bash
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```
   `ENCRYPTION_KEY` is required — the bot will not start without it, since every saved key/detail is encrypted at rest.

   Optional variables:
   ```ini
   WEBHOOK_URL=              # if set, runs in webhook mode instead of polling
   WEBHOOK_PATH=webhook      # path segment appended to WEBHOOK_URL
   PORT=8443                 # webhook listen port
   SUBSCRIPTION_PRICE_STARS=100   # price of the 30-day subscription, in Telegram Stars
   PRIVACY_POLICY_URL=       # defaults to this repo's GitHub Pages privacy-policy.html
   ```
3. Run the bot:
   ```bash
   python app.py
   ```

## Testing

```bash
python -m unittest discover
```

- `test_find_response.py` — checks `/find` renders the key as copyable Markdown
- `test_export_partition.py` — regression tests proving DM-saved and group-saved entries never cross chats, and that only `/numeric`, `/alphanumeric`, and Regenerate spend credits

Both `TELEGRAM_TOKEN` and `ENCRYPTION_KEY` must be set in the environment (or `.env`) before running tests, since importing `app.py` requires them.

## Notes

- The bot uses polling when `WEBHOOK_URL` is not set, webhooks otherwise.
- The SQLite file `authkeys.db` is created automatically and is git-ignored to avoid committing database contents.
- Deployable as-is on Heroku-style platforms via the included `Procfile`.

