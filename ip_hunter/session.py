"""HTTP session factory with retry logic and proxy support."""

from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ip_hunter.logger import log_debug


def make_session(
    token: str,
    auth_header: str = "Authorization",
    proxy: Optional[dict] = None,
) -> requests.Session:
    """Create a requests.Session with retry adapter, auth, and optional proxy.

    Args:
        token: API token / key for the provider.
        auth_header: Header name for authentication.
            If "Authorization", the value is set as "Bearer {token}".
            Otherwise the token is used as-is.
        proxy: Optional proxy config dict from parse_proxy().

    Returns:
        Configured requests.Session ready for use.
    """
    session = requests.Session()

    # Retry-стратегия: 3 попытки с экспоненциальным backoff
    retry_strategy = Retry(
        total=3,
        backoff_factor=1.0,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=5,
        pool_maxsize=10,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    # Авторизация
    if auth_header == "Authorization":
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        session.headers[auth_header] = token

    session.headers["Content-Type"] = "application/json"
    session.headers["Accept"] = "application/json"

    # Прокси
    if proxy:
        apply_proxy(session, proxy)
        log_debug(f"[Session] Прокси применён: {proxy.get('scheme', '?')}://{proxy.get('host', '?')}")

    log_debug("[Session] Сессия создана")
    return session


def apply_proxy(session: requests.Session, proxy_cfg: dict) -> None:
    """Apply proxy configuration to session.

    Args:
        session: Target requests session.
        proxy_cfg: Proxy config dict with keys: scheme, host, port, user, password.
    """
    scheme = proxy_cfg.get("scheme", "http")
    host = proxy_cfg.get("host", "")
    port = proxy_cfg.get("port", "")
    user = proxy_cfg.get("user", "")
    password = proxy_cfg.get("password", "")

    # Для SOCKS: DNS-резолв через прокси
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
