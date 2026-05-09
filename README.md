# Network Traffic Monitor

## Start

```bat
start.bat
```

Backend: http://localhost:8000  
Frontend: http://localhost:5173

## Telegram Alerts

Telegram credentials are loaded from environment variables or a root `.env`
file. Copy `.env.example` to `.env`, then replace the placeholder values:

```env
TELEGRAM_BOT_TOKEN=1234567890:token_from_botfather
TELEGRAM_CHAT_ID=123456789
```

If Telegram logs `Failed (401): Unauthorized`, the bot token is invalid,
revoked, or copied with extra characters. Regenerate the token in BotFather,
update `.env`, and restart the backend.

For group alerts, add the bot to the group and use that group's chat id. For a
personal chat, send one message to your bot first, then use your user chat id.
