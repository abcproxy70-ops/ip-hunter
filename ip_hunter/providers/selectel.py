"""Selectel provider — создание и удаление Floating IP через VPC Resell API.

Минимальный цикл: создать IP → проверить → удалить → повтор.
"""

import time
import threading
from typing import Optional

import requests

from ip_hunter.logger import log_debug, log_err, log_info, log_warn
from ip_hunter.providers.base import BaseProvider, ProviderResult
from ip_hunter.session import make_session


# ═══════════════════════════════════════════════════════════════════
# Авторизация: получение и обновление токена Keystone / Resell
# ═══════════════════════════════════════════════════════════════════

class KeystoneTokenManager:
    """Получает и кэширует токен. Два режима: keystone (user+pass) или static."""

    TOKEN_TTL = 23 * 3600  # 23 часа — с запасом до реального TTL в 24ч

    def __init__(self, cfg: dict, proxy: Optional[dict] = None) -> None:
        self._cfg = cfg
        self._proxy = proxy
        self._token: str = ""
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    # ── Публичный метод ──────────────────────────────────────────

    def get_token(self, force: bool = False) -> str:
        """Вернуть валидный токен. Обновить если истёк или force=True."""
        # Статический токен — без обновлений
        if self._cfg.get("token"):
            return self._cfg["token"]

        with self._lock:
            if not force and self._token and time.time() < self._expires_at:
                return self._token

        # Сетевой запрос ВНЕ лока
        token = self._authenticate()

        with self._lock:
            self._token = token
            self._expires_at = time.time() + self.TOKEN_TTL

        log_debug("[Keystone] Токен обновлён")
        return token

    # ── Внутренняя авторизация ───────────────────────────────────

    def _authenticate(self) -> str:
        """Keystone v3 password auth → X-Subject-Token."""
        username = self._cfg.get("username", "")
        password = self._cfg.get("password", "")
        account_id = self._cfg.get("account_id", "")
        project_name = self._cfg.get("project_name", "")

        if not username or not password:
            raise PermissionError("Selectel: нужны username + password или token")

        # Scope: project (если указан) или domain
        if project_name:
            scope = {"project": {"name": project_name, "domain": {"name": account_id}}}
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
        resp = self._post(url, json=payload)

        if resp.status_code == 201:
            token = resp.headers.get("X-Subject-Token", "")
            if not token:
                raise RuntimeError("Keystone: пустой X-Subject-Token")
            return token

        if resp.status_code == 401:
            raise PermissionError("Keystone 401: неверные credentials")

        raise RuntimeError(f"Keystone: HTTP {resp.status_code}")

    def _post(self, url: str, **kwargs) -> requests.Response:
        """Одноразовый POST-запрос (с прокси если настроен)."""
        sess = requests.Session()
        if self._proxy:
            from ip_hunter.session import apply_proxy
            apply_proxy(sess, self._proxy)
        try:
            return sess.post(url, timeout=(10, 30), **kwargs)
        finally:
            sess.close()


# ═══════════════════════════════════════════════════════════════════
# Провайдер: create_ip / delete_ip — и больше ничего лишнего
# ═══════════════════════════════════════════════════════════════════

class SelectelProvider(BaseProvider):
    """Selectel Floating IP: создание → удаление → повтор."""

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
        self._token_mgr: Optional[KeystoneTokenManager] = None

    # ── Инициализация ────────────────────────────────────────────

    def init_session(self) -> None:
        """Создать токен-менеджер и HTTP-сессию."""
        self._token_mgr = KeystoneTokenManager(self.cfg, self.proxy)
        token = self._token_mgr.get_token()
        self.session = make_session(token, "X-Auth-Token", self.proxy)
        log_info(f"[Selectel] Сессия готова ({self.current_account_label})")

    # ── Свойства ─────────────────────────────────────────────────

    @property
    def current_account_label(self) -> str:
        return self.cfg.get("label", self.cfg.get("account_id", "selectel"))

    @property
    def batch_size(self) -> int:
        return int(self.cfg.get("batch_size", 1))

    def get_regions(self) -> list[str]:
        return self.cfg.get("regions", ["ru-2", "ru-3"])

    # ── Создание IP ──────────────────────────────────────────────

    def create_ip(self, region: str) -> ProviderResult:
        """Создать один Floating IP в указанном регионе."""
        url = f"{self._base}/v2/floatingips/projects/{self._project_id}"
        payload = {"floatingips": [{"quantity": 1, "region": region}]}

        resp = self._request("POST", url, json=payload)

        # 401 — обновить токен, повторить один раз
        if resp.status_code == 401:
            self._refresh_token()
            resp = self._request("POST", url, json=payload)

        # Ошибки
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "?")
            raise RuntimeError(f"Rate limit (429) retry_after={retry}")

        if resp.status_code == 409:
            raise RuntimeError(f"Конфликт/квота (409): {resp.text[:200]}")

        if resp.status_code == 403:
            raise PermissionError(f"Selectel 403: {resp.text[:200]}")

        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Selectel HTTP {resp.status_code}: {resp.text[:200]}")

        # Парсим результат
        fips = resp.json().get("floatingips", [])
        for fip in fips:
            if fip.get("id") and fip.get("floating_ip_address"):
                return ProviderResult(
                    ip=fip["floating_ip_address"],
                    resource_id=fip["id"],
                    region=fip.get("region", region),
                    raw=fip,
                )

        raise RuntimeError("Selectel: пустой ответ floatingips")

    def create_ip_multi_region(self, per_region: dict[str, int]) -> list[ProviderResult]:
        """Создать IP в нескольких регионах одним запросом (батч)."""
        url = f"{self._base}/v2/floatingips/projects/{self._project_id}"
        payload = {
            "floatingips": [
                {"quantity": qty, "region": region}
                for region, qty in per_region.items()
            ]
        }

        resp = self._request("POST", url, json=payload)

        if resp.status_code == 401:
            self._refresh_token()
            resp = self._request("POST", url, json=payload)

        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After", "?")
            raise RuntimeError(f"Rate limit (429) retry_after={retry}")

        if resp.status_code == 409:
            raise RuntimeError(f"Конфликт/квота (409): {resp.text[:200]}")

        if resp.status_code == 403:
            raise PermissionError(f"Selectel 403: {resp.text[:200]}")

        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Selectel HTTP {resp.status_code}: {resp.text[:200]}")

        fips = resp.json().get("floatingips", [])
        results = [
            ProviderResult(
                ip=fip["floating_ip_address"],
                resource_id=fip["id"],
                region=fip.get("region", ""),
                raw=fip,
            )
            for fip in fips
            if fip.get("id") and fip.get("floating_ip_address")
        ]

        if not results:
            raise RuntimeError("Selectel: пустой ответ floatingips")

        return results

    # ── Удаление IP ──────────────────────────────────────────────

    def delete_ip(self, resource_id: str) -> None:
        """Удалить Floating IP по resource_id."""
        url = f"{self._base}/v2/floatingips/{resource_id}"

        resp = self._request("DELETE", url, timeout=(5, 10))

        # 401 — обновить токен, повторить
        if resp.status_code == 401:
            self._refresh_token()
            resp = self._request("DELETE", url, timeout=(5, 10))

        if resp.status_code not in (200, 204):
            raise RuntimeError(f"Selectel DELETE {resp.status_code}: {resp.text[:200]}")

        log_debug(f"[Selectel] Удалён {resource_id}")

    # ── Список IP (дополнительно — очистка мусора перед стартом) ─

    def list_ips(self) -> list[ProviderResult]:
        """Получить все активные Floating IP (для предварительной очистки)."""
        url = f"{self._base}/v2/floatingips"

        try:
            resp = self._request("GET", url)

            if resp.status_code == 401:
                self._refresh_token()
                resp = self._request("GET", url)

            if resp.status_code != 200:
                return []

            fips = resp.json().get("floatingips", [])
            return [
                ProviderResult(
                    ip=f["floating_ip_address"],
                    resource_id=f["id"],
                    region=f.get("region", ""),
                    raw=f,
                )
                for f in fips
                if f.get("id") and f.get("floating_ip_address")
            ]
        except Exception as exc:
            log_debug(f"[Selectel] list_ips: {exc}")
            return []

    # ── Приватные хелперы ────────────────────────────────────────

    def _request(self, method: str, url: str, timeout=None, **kwargs) -> requests.Response:
        """Выполнить HTTP-запрос через сессию."""
        if self.session is None:
            raise RuntimeError("Сессия не инициализирована, вызовите init_session()")
        return self.session.request(method, url, timeout=timeout or self.timeout, **kwargs)

    def _refresh_token(self) -> None:
        """Принудительно обновить токен и подставить в сессию."""
        if self._token_mgr is None:
            raise RuntimeError("TokenManager не инициализирован")
        log_warn("[Selectel] 401 — обновляем токен")
        new_token = self._token_mgr.get_token(force=True)
        if self.session is not None:
            self.session.headers["X-Auth-Token"] = new_token
