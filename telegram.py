"""Telegram notification sender for IP Hunter."""

import requests

from ip_hunter.logger import log_debug


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
            log_debug(f"[Telegram] HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        log_debug(f"[Telegram] Ошибка отправки: {exc}")
