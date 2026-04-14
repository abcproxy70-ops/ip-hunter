"""Proxy parsing, validation, and connectivity checking."""

import re
from typing import Optional
from urllib.parse import urlparse

import requests

from ip_hunter.logger import log_debug, log_err, log_ok


def parse_proxy(proxy_str: str) -> Optional[dict]:
    """Parse a proxy string into a config dict.

    Supported formats:
        - socks5://user:pass@host:port
        - socks4://host:port
        - http://user:pass@host:port
        - host:port  (defaults to http)

    Args:
        proxy_str: Raw proxy string from user input.

    Returns:
        Dict with keys: scheme, host, port, user, password.
        None if the string cannot be parsed.
    """
    proxy_str = proxy_str.strip()
    if not proxy_str:
        return None

    # Формат без схемы: host:port
    if "://" not in proxy_str:
        match = re.match(
            r"^(?:(?P<user>[^:@]+):(?P<pass>[^@]+)@)?(?P<host>[^:]+):(?P<port>\d+)$",
            proxy_str,
        )
        if not match:
            log_debug(f"[Proxy] Не удалось распарсить: {proxy_str}")
            return None
        return {
            "scheme": "http",
            "host": match.group("host"),
            "port": match.group("port"),
            "user": match.group("user") or "",
            "password": match.group("pass") or "",
        }

    # Формат с URI-схемой
    try:
        parsed = urlparse(proxy_str)
    except Exception as exc:
        log_debug(f"[Proxy] Ошибка urlparse: {exc}")
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https", "socks4", "socks5"):
        log_debug(f"[Proxy] Неизвестная схема: {scheme}")
        return None

    host = parsed.hostname or ""
    port = str(parsed.port) if parsed.port else ""
    if not host or not port:
        log_debug(f"[Proxy] Отсутствует host или port: {proxy_str}")
        return None

    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "user": parsed.username or "",
        "password": parsed.password or "",
    }


def apply_proxy_to_session(session: requests.Session, proxy_cfg: dict) -> None:
    """Apply proxy configuration to an existing session.

    Handles SOCKS DNS resolution:
        - socks5 → socks5h:// (DNS через прокси)
        - socks4 → socks4a://

    Args:
        session: Target requests.Session.
        proxy_cfg: Dict from parse_proxy().
    """
    scheme = proxy_cfg.get("scheme", "http")
    host = proxy_cfg.get("host", "")
    port = proxy_cfg.get("port", "")
    user = proxy_cfg.get("user", "")
    password = proxy_cfg.get("password", "")

    # DNS через прокси для SOCKS
    if scheme == "socks5":
        scheme = "socks5h"
    elif scheme == "socks4":
        scheme = "socks4a"

    if user and password:
        proxy_url = f"{scheme}://{user}:{password}@{host}:{port}"
    elif user:
        proxy_url = f"{scheme}://{user}@{host}:{port}"
    else:
        proxy_url = f"{scheme}://{host}:{port}"

    session.proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    log_debug(f"[Proxy] Применён к сессии: {scheme}://{host}:{port}")


def check_proxy(proxy_cfg: dict, timeout: int = 10) -> bool:
    """Verify proxy connectivity by fetching external IP.

    Args:
        proxy_cfg: Dict from parse_proxy().
        timeout: Request timeout in seconds.

    Returns:
        True if the proxy is functional, False otherwise.
    """
    session = requests.Session()
    apply_proxy_to_session(session, proxy_cfg)

    try:
        resp = session.get(
            "https://api.ipify.org?format=json",
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        external_ip = data.get("ip", "???")
        log_ok(f"[Proxy] Работает. Внешний IP: {external_ip}")
        return True
    except requests.exceptions.ConnectionError as exc:
        log_err(f"[Proxy] Ошибка подключения: {exc}")
        return False
    except requests.exceptions.Timeout:
        log_err(f"[Proxy] Таймаут ({timeout}с)")
        return False
    except requests.exceptions.RequestException as exc:
        log_err(f"[Proxy] Ошибка запроса: {exc}")
        return False
    except ValueError as exc:
        log_err(f"[Proxy] Ошибка JSON: {exc}")
        return False
    finally:
        try:
            session.close()
        except Exception as exc:
            log_debug(f"[Proxy] Ошибка закрытия сессии: {exc}")
