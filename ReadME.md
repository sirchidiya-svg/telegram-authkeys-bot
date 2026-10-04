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

### 5. Dedicated User Feedback & Feature Suggestions
- **`/feedback`**: Exclusively for user experience insights, what users like, and feature requests.
- **Clear Guidance**: Outlines specific prompts for sharing ideas without mixing technical bugs into the suggestion pipeline.

### 6. Technical Support & Defect Reporting
- **`/support`**: Dedicated technical reporting channel for glitches, malfunctions, or command errors.
- **Structured Bug Intake**: Prompts users for steps taken, actual behavior, expected outcome, and optional photo/screenshot proof with mandatory text descriptions.
- **Separate Ticket Queue**: Stored in PostgreSQL with file IDs and routed directly to the administrative support queue.

### 7. Transparent Refund Processing & Admin Dashboards
- **Self-Service Initiation**: Users request refunds directly through `/paysupport`.
- **Transparent Policy Terms**:
  - All requests reviewed within **3 to 5 working days**.
  - Refunds require a verifiable technical defect or unresolvable service fault.
  - Optional photo/screenshot attachments supported; text explanations required.
- **Dual Rejection Pathways**:
  - **⚡ Fast Dismiss**: Automatically notifies user with standard corporate policy terms.
  - **✍️ Custom Reason**: Prompts admin for a custom explanation dispatched directly to the customer.
- **Administrative Queue Management**:
  - Interactive queues for refunds (`/admin_refunds`), feedback (`/admin_feedbacks`), and support tickets (`/admin_support`).
  - Seamless in-place updates on Telegram message cards (supports both text and photo captions).
  - Built-in sandbox simulation (`/test_refund`) for end-to-end admin verification without spending real Stars.

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
| `/paysupport` | None | Access Telegram Stars refund requests. |
| `/support` | None | Report technical errors, glitches, or system defects. |
| `/feedback` | None | Submit feature suggestions and general feedback. |
| `/team_sharing` | `on` \| `off` | *(Group Admins only)* Toggles collective secret sharing. |
| `/help` | None | Bot help, user guide, and support navigation. |

### Secret Administrator Commands
*These commands are guarded by `ADMIN_USER_ID` checks and are omitted from user command menus:*

| Command | Access | Description |
| :--- | :--- | :--- |
| `/admin_refunds` | Admin Only | Review, approve, or dismiss pending refund requests. |
| `/admin_support` | Admin Only | Inspect and resolve incoming technical support tickets. |
| `/admin_feedbacks` | Admin Only | Review submitted user feedback and feature suggestions. |
| `/test_refund` | Admin Only | Generates a mock refund request to safely test approval/dismissal workflows. |

---

## 🗄️ Database Architecture

The PostgreSQL database initializes nine tables automatically on startup:

1. **`saved_keys`**: Stores user-saved credentials, encrypted details, Fernet ciphertexts, titles, and ownership metadata.
2. **`users`**: Tracks user trial start dates and subscription expiration timestamps.
3. **`usage_log`**: Records daily command executions per user for rate/credit enforcement.
4. **`generated_keys`**: Maps temporary chat/message IDs to generated keys so `/save` can verify authenticity.
5. **`group_settings`**: Stores group-specific configurations such as team sharing status.
6. **`payments`**: Audit ledger recording Telegram `charge_id`, user ID, amount in Stars, and timestamps.
7. **`refund_requests`**: Stores refund submissions, transaction references, user explanations, attached photo IDs, admin rejection notes, and queue statuses (`pending`, `approved`, `rejected`).
8. **`feedback_reports`**: Stores user feedback, feature suggestions, timestamps, photo file IDs, and review statuses (`pending`, `reviewed`).
9. **`support_tickets`**: Stores bug reports, technical defect details, photo proof, timestamps, and resolution statuses (`pending`, `resolved`).

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
