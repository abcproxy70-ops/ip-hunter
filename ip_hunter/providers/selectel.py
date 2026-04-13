"""Selectel provider — Floating IP management via VPC Resell API."""

import threading
import time
from dataclasses import dataclass
from typing import Optional

import requests

from ip_hunter.logger import log_debug, log_err, log_info, log_warn
from ip_hunter.providers.base import BaseProvider, DailyLimitError, ProviderResult
from ip_hunter.session import make_session


class _RetryAfterRefresh(Exception):
    """Internal: signal that token was refreshed and request should be retried."""


@dataclass
class _TokenState:
    """Internal token state."""
    token: str = ""
    expires_at: float = 0.0
    consecutive_auth_failures: int = 0


class KeystoneTokenManager:
    """Auto-refreshing token manager: Keystone, Resell, or Static mode."""
    TOKEN_TTL_SEC: float = 23 * 3600
    MAX_AUTH_FAILURES: int = 3

    def __init__(self, cfg: dict, proxy: Optional[dict] = None) -> None:
        self._cfg = cfg
        self._proxy = proxy
        self._state = _TokenState()
        self._lock = threading.Lock()
        self._mode = self._detect_mode()
        log_debug(f"[Keystone] Режим авторизации: {self._mode}")

    def _detect_mode(self) -> str:
        """Detect auth mode from config keys."""
        if self._cfg.get("token"):
            return "static"
        if self._cfg.get("username") and self._cfg.get("password"):
            return "keystone"
        if self._cfg.get("api_key"):
            return "resell"
        raise ValueError(
            "Selectel: нужен token, username+password, или api_key"
        )

    def get_token(self, force_refresh: bool = False) -> str:
        """Return a valid token, refreshing if needed."""
        with self._lock:
            if self._mode == "static":
                return self._cfg["token"]
            now = time.time()
            if not force_refresh and self._state.token and now < self._state.expires_at:
                return self._state.token
        # Refresh ВНЕ лока (сетевой вызов)
        return self._refresh()

    def _refresh(self) -> str:
        """Perform token refresh via network call."""
        try:
            if self._mode == "keystone":
                token = self._keystone_auth()
            else:
                token = self._resell_auth()
        except PermissionError:
            raise
        except Exception as exc:
            with self._lock:
                self._state.consecutive_auth_failures += 1
                fails = self._state.consecutive_auth_failures
            log_err(f"[Keystone] Ошибка авторизации ({fails}): {exc}")
            if fails >= self.MAX_AUTH_FAILURES:
                raise PermissionError(
                    f"Selectel: {fails} ошибок авторизации подряд"
                ) from exc
            raise

        with self._lock:
            self._state.token = token
            self._state.expires_at = time.time() + self.TOKEN_TTL_SEC
            self._state.consecutive_auth_failures = 0
        log_debug("[Keystone] Токен обновлён")
        return token

    def _keystone_auth(self) -> str:
        """Authenticate via Keystone v3 password method."""
        username = self._cfg["username"]
        password = self._cfg["password"]
        account_id = self._cfg.get("account_id", "")
        project_name = self._cfg.get("project_name", "")

        scope: dict
        if project_name:
            scope = {
                "project": {
                    "name": project_name,
                    "domain": {"name": account_id},
                }
            }
        else:
            scope = {"domain": {"name": account_id}}

        payload = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "domain": {"name": account_id},
                            "password": password,
                        }
                    },
                },
                "scope": scope,
            }
        }

        url = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
        resp = self._do_request("POST", url, json=payload)

        if resp.status_code == 201:
            token = resp.headers.get("X-Subject-Token", "")
            if not token:
                raise RuntimeError("Keystone: пустой X-Subject-Token")
            return token
        if resp.status_code == 401:
            with self._lock:
                self._state.consecutive_auth_failures += 1
            raise PermissionError(f"Keystone 401: неверные credentials")
        raise RuntimeError(f"Keystone: HTTP {resp.status_code}")

    def _resell_auth(self) -> str:
        """Authenticate via Resell token endpoint."""
        api_key = self._cfg["api_key"]
        account_id = self._cfg.get("account_id", "")

        url = "https://api.selectel.ru/vpc/resell/v2/tokens"
        headers = {"X-Token": api_key, "Content-Type": "application/json"}
        body = {"token": {"account_name": account_id}}

        resp = self._do_request("POST", url, json=body, headers=headers)
        if resp.status_code in (200, 201):
            data = resp.json()
            token = data.get("token", {}).get("id", "")
            if not token:
                raise RuntimeError("Resell: пустой token.id")
            return token
        raise RuntimeError(f"Resell: HTTP {resp.status_code}")

    def _do_request(self, method: str, url: str,
                    json: Optional[dict] = None,
                    headers: Optional[dict] = None) -> requests.Response:
        """Execute an HTTP request with optional proxy."""
        sess = requests.Session()
        if headers:
            sess.headers.update(headers)
        proxies: Optional[dict] = None
        if self._proxy:
            from ip_hunter.proxy import apply_proxy_to_session
            apply_proxy_to_session(sess, self._proxy)
        try:
            return sess.request(method, url, json=json, timeout=(10, 30))
        finally:
            try:
                sess.close()
            except Exception as exc:
                log_debug(f"[Keystone] Ошибка закрытия сессии: {exc}")


class SelectelProvider(BaseProvider):
    """Selectel Floating IP provider via VPC Resell API."""
    name: str = "selectel"

    def __init__(
        self,
        cfg: dict,
        timeout: tuple[int, int] = (10, 30),
        proxy: Optional[dict] = None,
    ) -> None:
        super().__init__(cfg, timeout, proxy)
        self._base: str = cfg.get(
            "base_url", "https://api.selectel.ru/vpc/resell/"
        ).rstrip("/")
        self._project_id: str = cfg.get("project_id", "")
        self._instance_label: str = cfg.get("label", cfg.get("account_id", "selectel"))
        self._batch_size: int = int(cfg.get("batch_size", 2))
        self._token_mgr: Optional[KeystoneTokenManager] = None

    def init_session(self) -> None:
        """Initialize Keystone token manager and HTTP session."""
        self._token_mgr = KeystoneTokenManager(self.cfg, self.proxy)
        token = self._token_mgr.get_token()
        self.session = make_session(token, "X-Auth-Token", self.proxy)
        log_info(f"[Selectel] Сессия готова ({self._instance_label})")

    @property
    def batch_size(self) -> int:
        """Return configured batch size."""
        return self._batch_size

    @property
    def current_account_label(self) -> str:
        """Return human-readable account label."""
        return self._instance_label

    def get_regions(self) -> list[str]:
        """Return configured region list."""
        return self.cfg.get("regions", ["ru-2", "ru-3"])

    def create_ip(self, region: str) -> ProviderResult:
        """Allocate a single Floating IP in the given region."""
        results = self._do_create(
            [{"quantity": 1, "region": region}], region
        )
        if not results:
            raise RuntimeError("Selectel create_ip: пустой ответ")
        return results[0]

    def create_ip_batch(self, region: str, quantity: int) -> list[ProviderResult]:
        """Allocate multiple Floating IPs in one region."""
        return self._do_create(
            [{"quantity": quantity, "region": region}], region
        )

    def create_ip_multi_region(self, per_region: dict[str, int]) -> list[ProviderResult]:
        """Allocate Floating IPs across multiple regions."""
        body = [{"quantity": qty, "region": r} for r, qty in per_region.items()]
        return self._do_create(body, "multi")

    def _do_create(
        self, fips_body: list[dict], default_region: str, _retry: bool = True
    ) -> list[ProviderResult]:
        """POST floatingips and parse response."""
        url = f"{self._base}/v2/floatingips/projects/{self._project_id}"
        payload = {"floatingips": fips_body}
        if self.session is None: raise RuntimeError("Вызовите init_session() перед create")
        resp = self.session.post(url, json=payload, timeout=self.timeout)
        try:
            return self._parse_create_response(resp, default_region, _retry)
        except _RetryAfterRefresh:
            # Токен обновлён — повторяем запрос БЕЗ retry чтобы не зациклиться
            resp2 = self.session.post(url, json=payload, timeout=self.timeout)
            return self._parse_create_response(resp2, default_region, False)

    def _parse_create_response(
        self,
        resp: requests.Response,
        region: str,
        allow_retry: bool,
    ) -> list[ProviderResult]:
        """Parse create response. КРИТИЧНО: на 409 парсим тело — IP могли уже создаться."""
        # 401 — обновить токен, caller сделает retry через _do_create(_retry=False)
        if resp.status_code == 401 and allow_retry:
            log_warn("[Selectel] 401 — обновляем токен")
            self._refresh_and_retry()
            raise _RetryAfterRefresh()

        # 429 — rate limit
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "?")
            raise RuntimeError(
                f"Rate limit (429) retry_after={retry_after}"
            )

        # 409 — конфликт/квота, НО IP могли создаться
        if resp.status_code == 409:
            try:
                data = resp.json()
                fips = data.get("floatingips", [])
                results = [
                    ProviderResult(
                        ip=fip["floating_ip_address"],
                        resource_id=fip["id"],
                        region=fip.get("region", region),
                        raw=fip,
                    )
                    for fip in fips
                    if fip.get("id") and fip.get("floating_ip_address")
                ]
                if results:
                    log_warn(
                        f"[Selectel] 409 но получены {len(results)} IP (partial success)"
                    )
                    return results
            except Exception as exc:
                log_debug(f"[Selectel] 409 парсинг тела не удался: {exc}")
            raise RuntimeError(
                f"Конфликт/квота (409): {resp.text[:200]}"
            )

        # 403 — доступ запрещён
        if resp.status_code == 403:
            raise PermissionError(
                f"Selectel 403: доступ запрещён ({resp.text[:200]})"
            )

        # Любой другой не-2xx
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Selectel HTTP {resp.status_code}: {resp.text[:300]}"
            )

        # Успех — парсим floatingips
        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError(f"Selectel: невалидный JSON: {exc}") from exc

        fips = data.get("floatingips", [])
        results = [
            ProviderResult(
                ip=fip["floating_ip_address"],
                resource_id=fip["id"],
                region=fip.get("region", region),
                raw=fip,
            )
            for fip in fips
            if fip.get("id") and fip.get("floating_ip_address")
        ]

        if not results:
            raise RuntimeError(
                f"Selectel: пустой ответ floatingips: {data}"
            )
        return results

    def delete_ip(self, resource_id: str, _retry: bool = True) -> None:
        """Release a Floating IP by resource_id."""
        url = f"{self._base}/v2/floatingips/{resource_id}"
        if self.session is None: raise RuntimeError("Сессия не инициализирована")
        resp = self.session.delete(url, timeout=(5, 10))

        if resp.status_code == 401 and _retry:
            log_warn("[Selectel] DELETE 401 — обновляем токен")
            self._refresh_and_retry()
            self.delete_ip(resource_id, _retry=False)
            return

        if resp.status_code not in (200, 204):
            log_err(
                f"[Selectel] DELETE {resource_id}: HTTP {resp.status_code}"
            )
            raise RuntimeError(
                f"Selectel DELETE {resp.status_code}: {resp.text[:200]}"
            )
        log_debug(f"[Selectel] Удалён {resource_id}")

    def _refresh_and_retry(self) -> None:
        """Force-refresh the token and update session header."""
        if self._token_mgr is None:
            raise RuntimeError("TokenManager не инициализирован")
        new_token = self._token_mgr.get_token(force_refresh=True)
        if self.session is not None:
            self.session.headers["X-Auth-Token"] = new_token
        log_debug("[Selectel] Токен обновлён в сессии")
