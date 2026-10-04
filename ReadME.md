# 🔑 AuthKeys Generator Bot (`@AuthKeys_Bot`)

A high-performance, security-focused Telegram bot built in Python (`python-telegram-bot` v20+ `asyncio`) designed for generating cryptographically secure numeric and alphanumeric authentication keys, maintaining an encrypted secret vault, and facilitating team secret sharing.

Hosted on **Railway** with **PostgreSQL** and encrypted at rest with **Fernet (AES-128-CBC + HMAC-SHA256)**.

---

## ✨ Features Overview

### 1. Cryptographic Key Generation
- **`/numeric`**: Generates randomized 8-digit numeric passkeys.
- **`/alphanumeric`**: Generates 8-character mixed uppercase and numerical keys.
- **Interactive Regeneration**: Message-bound `🔄 Regenerate` button allowing immediate re-generation with per-user rate limiting (3-second anti-spam).
- **Inline Mode (`@AuthKeys_Bot`)**: Trigger instant key generation anywhere across Telegram (DMs, channels, groups) with custom preview thumbnail icons.

### 2. Zero-Knowledge Encrypted Vault
- **Encrypted Storage**: Save keys by replying to bot-generated output with `/save <title> <description>`. Saved records are encrypted symmetrically via Fernet before database writes.
- **Fast Retrieval**: Query credentials with `/find <title>` formatted with monospace code blocks for 1-tap copying.
- **Export & Deletion (GDPR/CCPA)**:
  - `/export_my_data` dumps all chat-scoped records.
  - `/delete <title>` removes individual entries.
  - `/delete_all_my_data` purges every record associated with the user across all chats.

### 3. Group Team Secret Sharing
- Group administrators can toggle team mode using `/team_sharing on` or `/team_sharing off`.
- When active, any member in the group can search and retrieve group-shared credentials, with automatic attribution indicating who originally saved the key.

### 4. Monetization & Usage Tiers (Telegram Stars)
- **Free Trial**: 10 generations per day during a 7-day initial trial.
- **Subscriber Tier**: 30 days of unlimited generations purchased with Telegram Stars (XTR) via `/subscribe`.
- **Status Inspection**: `/status` displays subscription expiration, trial days, remaining daily credits, and a verified role badge for administrators.

### 5. In-Bot Feedback & Defect Reporting
- **Dedicated `/feedback` Command**: Users receive structured guidance on how to submit clear, actionable feedback.
- **Strict Validation**: Text explanation is mandatory. Submitting a standalone screenshot without context is rejected.
- **Queue Pipeline**: Feedback reports are stored in PostgreSQL with photo file IDs and routed to the administrator queue.

### 6. Transparent Refund Processing & Admin Queue
- **Self-Service Initiation**: Users request refunds through `/paysupport`.
- **Transparent Policy Requirements**:
  - Reviews are processed within **3 to 5 working days**.
  - A refund is not automatic; users must submit a valid written reason detailing system defects or dissatisfaction.
  - Screenshots/photos may be attached as optional supporting evidence.
  - Approved refunds immediately trigger Telegram's `refund_star_payment` API, revoke the user's subscription, and remove the charge record.
- **Admin Counter & Dedicated Queues**:
  - New refund and feedback submissions trigger admin notifications displaying live queue counts (e.g., `📋 Pending Refund Requests: 2`).
  - Interactive pagination/selection menus allow the admin to view reasons, inspect attached screenshots, and execute or dismiss requests.
- **Built-in Mock Testing**: Secret `/test_refund` command creates sandbox refund requests for testing buttons and notifications without spending real Stars.

---

## 📋 Commands Reference

### Public User Commands
| Command | Arguments | Description |
| :--- | :--- | :--- |
| `/start` | None | Welcome banner, quick-start guide, and privacy policy link. |
| `/numeric` | None | Generates an 8-digit numeric authentication key. |
| `/alphanumeric` | None | Generates an 8-character alphanumeric key. |
| `/save` | `{title} {details}` | Saves a key (must reply directly to a bot-generated key). |
| `/find` | `{title}` | Decrypts and displays a saved credential by title. |
| `/delete` | `{title}` | Deletes a specific saved key by title. |
| `/delete_all_my_data` | None | Two-step permanent wipe of all user records. |
| `/export_my_data` | None | Exports all saved data belonging to the current chat. |
| `/status` | None | Shows quota, subscription expiry, and verified admin role. |
| `/subscribe` | None | Sends a Telegram Stars invoice for 30 days of unlimited access. |
| `/paysupport` | None | Access billing assistance and launch the refund workflow. |
| `/feedback` | None | Opens the guided feedback submission form. |
| `/team_sharing` | `on` \| `off` | *(Group Admins only)* Toggles collective secret sharing. |
| `/help` | None | Displays developer contact and sponsorship information. |

### Secret Administrator Commands
*These commands are guarded by `ADMIN_USER_ID` checks and are omitted from user command menus:*

| Command | Access | Description |
| :--- | :--- | :--- |
| `/admin_refunds` | Admin Only | Displays the pending refund queue with interactive approval cards. |
| `/admin_feedbacks` | Admin Only | Displays the pending feedback queue with photo inspection. |
| `/test_refund` | Admin Only | Generates a mock refund request to test approval workflows safely. |

---

## 🗄️ Database Architecture

The PostgreSQL database initializes seven tables automatically on startup:

1. **`saved_keys`**: Stores user-saved credentials, encrypted details, Fernet ciphertexts, titles, and ownership metadata.
2. **`users`**: Tracks user trial start dates and subscription expiration timestamps.
3. **`usage_log`**: Records daily command executions per user for rate/credit enforcement.
4. **`generated_keys`**: Maps temporary chat/message IDs to generated keys so `/save` can verify authenticity.
5. **`group_settings`**: Stores group-specific configurations such as team sharing status.
6. **`payments`**: Audit ledger recording Telegram `charge_id`, user ID, amount in Stars, and timestamps.
7. **`refund_requests`**: Stores refund submissions, transaction references, user explanations, attached photo IDs, and queue statuses (`pending`, `approved`, `rejected`).
8. **`feedback_reports`**: Stores user feedback, bug reports, timestamps, photo file IDs, and review statuses (`pending`, `reviewed`).

---

## ⚙️ Environment Configuration

Set these variables in your **Railway Project Settings > Variables** (or `.env` locally):

| Variable | Required | Description |
| :--- | :--- | :--- |
| `TELEGRAM_TOKEN` | **Yes** | Telegram Bot API token obtained from `@BotFather`. |
| `DATABASE_URL` | **Yes** | PostgreSQL connection string (`postgresql://...`). |
| `ENCRYPTION_KEY` | **Yes** | URL-safe 32-byte base64 encryption key for Fernet. |
| `ADMIN_USER_ID` | **Yes** | Your numeric Telegram ID (obtained from `@userinfobot`). |
| `SUBSCRIPTION_PRICE_STARS`| No | Price in Stars for 30-day access (Default: `100`). |
| `WEBHOOK_URL` | No | Public domain of the service for webhook mode; omit for polling. |
| `WEBHOOK_PATH` | No | Webhook endpoint path (Default: `webhook`). |
| `PORT` | No | Webhook listening port (Default: `8443` or Railway's `$PORT`). |
| `PRIVACY_POLICY_URL` | No | Hosted URL for the public privacy policy webpage. |

---

## 🚀 Deployment Instructions

### 1. Generate Encryption Key
Run this in any Python environment:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
