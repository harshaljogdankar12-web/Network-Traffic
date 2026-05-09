"""
Notification module: Telegram alerts + Firebase Realtime Database buzzer.

Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in your environment before
starting the backend. Telegram returns 401 Unauthorized when the bot token is
invalid, revoked, or includes extra characters.
"""

import os
import re
import time
from datetime import datetime
from pathlib import Path

import httpx


def _load_env_file() -> None:
    """Load simple KEY=VALUE lines from .env without adding a dependency."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    for env_path in candidates:
        if not env_path.exists():
            continue
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip().strip('"').strip("'")
        break


_load_env_file()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

FIREBASE_BASE_URL = os.getenv(
    "FIREBASE_BASE_URL",
    "https://waterdtection-default-rtdb.firebaseio.com",
).rstrip("/")
FIREBASE_BUZZER_PATH = os.getenv(
    "FIREBASE_BUZZER_PATH",
    "Netwrok_traffic/Buzzer",
).strip("/")

TELEGRAM_COOLDOWN = int(os.getenv("TELEGRAM_COOLDOWN", "20"))
TELEGRAM_TOKEN_RE = re.compile(r"^\d+:[A-Za-z0-9_-]{30,}$")

_telegram_sent_at: dict[str, float] = {}
_last_buzzer_value: int = -1
_telegram_checked = False


def _telegram_can_send(key: str) -> bool:
    now = time.time()
    if now - _telegram_sent_at.get(key, 0) >= TELEGRAM_COOLDOWN:
        _telegram_sent_at[key] = now
        return True
    return False


def _telegram_config_error() -> str | None:
    if not TELEGRAM_BOT_TOKEN:
        return "TELEGRAM_BOT_TOKEN is not set"
    if not TELEGRAM_CHAT_ID:
        return "TELEGRAM_CHAT_ID is not set"
    if not TELEGRAM_TOKEN_RE.match(TELEGRAM_BOT_TOKEN):
        return "TELEGRAM_BOT_TOKEN format looks invalid"
    return None


def _masked_bot_token() -> str:
    if not TELEGRAM_BOT_TOKEN:
        return "<empty>"
    if ":" not in TELEGRAM_BOT_TOKEN:
        return f"{TELEGRAM_BOT_TOKEN[:4]}... len={len(TELEGRAM_BOT_TOKEN)}"
    bot_id, secret = TELEGRAM_BOT_TOKEN.split(":", 1)
    return f"{bot_id}:...{secret[-6:]} len={len(TELEGRAM_BOT_TOKEN)}"


def _log_telegram_failure(status_code: int, body: str) -> None:
    if status_code == 401:
        print(
            "[Telegram] Failed (401): Unauthorized. Check that "
            "TELEGRAM_BOT_TOKEN is the current token from BotFather."
        )
        return
    print(f"[Telegram] Failed ({status_code}): {body[:200]}")


async def _check_telegram_bot() -> bool:
    """Ask Telegram whether the configured bot token is valid."""
    global _telegram_checked
    if _telegram_checked:
        return True
    _telegram_checked = True

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe"
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(url)
        if response.status_code == 200:
            data = response.json().get("result", {})
            print(
                "[Telegram] Bot verified: "
                f"@{data.get('username', 'unknown')} using {_masked_bot_token()}"
            )
            return True
        print(
            "[Telegram] Bot token rejected by getMe "
            f"({response.status_code}) using {_masked_bot_token()}: {response.text[:200]}"
        )
        return False
    except Exception as exc:
        print(f"[Telegram] Bot verification error using {_masked_bot_token()}: {exc}")
        return True


async def set_buzzer(value: int) -> None:
    """Write integer 1 (critical) or 0 (safe) to Firebase Buzzer."""
    global _last_buzzer_value
    if _last_buzzer_value == value:
        return
    _last_buzzer_value = value

    try:
        url = f"{FIREBASE_BASE_URL}/{FIREBASE_BUZZER_PATH}.json"
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.put(
                url,
                content=str(value),
                headers={"Content-Type": "application/json"},
            )
        if response.status_code == 200:
            print(f"[Firebase] Buzzer -> {value}")
        else:
            print(f"[Firebase] Failed ({response.status_code}): {response.text[:200]}")
    except Exception as exc:
        print(f"[Firebase] Error: {exc}")


async def _send_telegram(text: str) -> None:
    config_error = _telegram_config_error()
    if config_error:
        print(f"[Telegram] Not configured: {config_error}. Would send:\n{text}")
        return
    if not await _check_telegram_bot():
        return

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.post(
                url,
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": text,
                    "parse_mode": "HTML",
                },
            )
        if response.status_code == 200:
            print("[Telegram] Alert sent")
        else:
            _log_telegram_failure(response.status_code, response.text)
    except Exception as exc:
        print(f"[Telegram] Error: {exc}")


async def notify_critical(
    event_type: str,
    details: str,
    rps: int = 0,
    sim_users: int = 0,
) -> None:
    """
    Called every tick when a critical condition is detected.
    - Firebase Buzzer -> 1, only when state changes.
    - Telegram alert -> sent once per TELEGRAM_COOLDOWN seconds.
    """
    await set_buzzer(1)

    if not _telegram_can_send(event_type):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    telegram_text = (
        "<b>CRITICAL ALERT - Network Traffic Monitor</b>\n\n"
        f"<b>Event:</b> {event_type}\n"
        f"<b>Details:</b> {details}\n"
        f"<b>RPS:</b> {rps} req/s\n"
        f"<b>Sim Users:</b> {sim_users}\n"
        f"<b>Time:</b> {timestamp}"
    )
    print(f"[Notifier] Telegram -> {event_type}")
    await _send_telegram(telegram_text)


async def clear_buzzer() -> None:
    """Called when threat resolves; sets Firebase Buzzer back to 0."""
    await set_buzzer(0)
