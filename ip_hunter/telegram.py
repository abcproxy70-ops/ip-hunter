"""Telegram notification sender for IP Hunter."""

import requests

from ip_hunter.logger import log_debug, log_warn


def send_telegram(bot_token: str, admin_id: str, text: str,
                  parse_mode: str = "HTML") -> None:
    """Send a message via Telegram Bot API.

    Args:
        bot_token: Telegram bot token.
        admin_id: Chat ID of the admin.
        text: Message text.
        parse_mode: Parse mode (HTML or Markdown).
    """
    if not bot_token or not admin_id:
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": admin_id,
        "text": text,
        "parse_mode": parse_mode,
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code != 200:
            log_warn(f"[Telegram] HTTP {resp.status_code}: {resp.text[:200]}")
            # Если HTML-парсинг не прошёл — повторяем без parse_mode
            if resp.status_code == 400 and "parse" in resp.text.lower():
                payload.pop("parse_mode", None)
                resp2 = requests.post(url, json=payload, timeout=10)
                if resp2.status_code != 200:
                    log_warn(f"[Telegram] Retry без parse_mode: HTTP {resp2.status_code}")
    except Exception as exc:
        log_warn(f"[Telegram] Ошибка отправки: {exc}")
