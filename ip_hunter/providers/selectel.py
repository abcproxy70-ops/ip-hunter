"""Selectel provider — Floating IP через VPC Resell API.

Логика 1:1 из v11 монолита:
- KeystoneTokenManager с поддержкой keystone (user+pass) и resell (api_key) режимов
- create_ip / create_ip_batch с авто-обновлением токена при 401
- Синхронное удаление в основном потоке
- batch_size из конфига
"""

import json
import time
import threading
from typing import Optional

import requests

from ip_hunter.logger import log_debug, log_err, log_info, log_ok, log_warn
from ip_hunter.providers.base import BaseProvider, ProviderResult
from ip_hunter.session import make_session
from ip_hunter.proxy import apply_proxy_to_session


# ═══════════════════════════════════════════════════════════════════
# Keystone Token Manager — из v11, поддержка keystone + resell + static
# ═══════════════════════════════════════════════════════════════════

class KeystoneTokenManager:
    """Авто-обновление Keystone/Resell токена Selectel. Логика из v11."""

    KEYSTONE_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
    RESELL_TOKENS_URL = "https://api.selectel.ru/vpc/resell/v2/tokens"

    def __init__(self, account_id="", username="", password="",
                 api_key="", project_name="", project_id="",
                 proxy: Optional[dict] = None):
        self.account_id = account_id
        self.username = username
        self.password = password
        self.api_key = api_key
        self.project_name = project_name
        self.project_id = project_id
        self._token: str = ""
        self._token_expires: Optional[float] = None
        self._lock = threading.Lock()
        self._proxy = proxy
        self._consecutive_auth_failures: int = 0
        self.MAX_AUTH_FAILURES: int = 3

        if username and password and account_id:
            self._mode = "keystone"
        elif api_key and account_id:
            self._mode = "resell"
        else:
            self._mode = "static"

    @property
    def mode(self) -> str:
        return self._mode

    def get_token(self, force_refresh: bool = False) -> str:
        if self._mode == "static":
            return self._token

        with self._lock:
            need_refresh = (
                force_refresh
                or not self._token
                or (self._token_expires and time.time() > self._token_expires - 600)
            )
            if need_refresh:
                if self._mode == "keystone":
                    self._refresh_keystone()
                elif self._mode == "resell":
                    self._refresh_resell()
            return self._token

    def set_static_token(self, token: str):
        self._token = token
        self._token_expires = None

    def _refresh_keystone(self):
        if self.project_name:
            scope = {"project": {"name": self.project_name, "domain": {"name": self.account_id}}}
        else:
            scope = {"domain": {"name": self.account_id}}

        payload = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.username,
                            "domain": {"name": self.account_id},
                            "password": self.password,
                        }
                    },
                },
                "scope": scope,
            }
        }

        if self._consecutive_auth_failures == 0:
            log_info("Selectel: обновление Keystone-токена...")
        else:
            log_debug(f"Selectel: обновление Keystone-токена (попытка {self._consecutive_auth_failures + 1}/{self.MAX_AUTH_FAILURES})...")

        try:
            s = requests.Session()
            if self._proxy:
                apply_proxy_to_session(s, self._proxy)
            resp = s.post(self.KEYSTONE_URL, json=payload,
                          headers={"Content-Type": "application/json"}, timeout=15)
            s.close()
            if resp.status_code == 201:
                new_token = resp.headers.get("X-Subject-Token", "")
                if new_token:
                    self._token = new_token
                    self._token_expires = time.time() + 23 * 3600
                    self._consecutive_auth_failures = 0
                    log_ok("Selectel: Keystone-токен обновлён")
                    return
                raise RuntimeError("X-Subject-Token отсутствует")
            if resp.status_code == 401:
                self._consecutive_auth_failures += 1
                log_err(f"[SELECTEL] Keystone HTTP 401 (попытка {self._consecutive_auth_failures}/{self.MAX_AUTH_FAILURES})")
                if self._consecutive_auth_failures >= self.MAX_AUTH_FAILURES:
                    raise PermissionError(
                        f"Keystone: {self.MAX_AUTH_FAILURES} подряд 401 — credentials невалидны "
                        f"(user: {self.username}, account: {self.account_id})"
                    )
                raise RuntimeError("Keystone HTTP 401: Unauthorized")
            raise RuntimeError(f"Keystone HTTP {resp.status_code}: {resp.text[:300]}")
        except (PermissionError, RuntimeError):
            raise
        except requests.RequestException as e:
            log_err(f"Selectel: ошибка Keystone: {e}")
            raise

    def _refresh_resell(self):
        if self._consecutive_auth_failures == 0:
            log_info("Selectel: обновление Resell-токена...")
        else:
            log_debug(f"Selectel: обновление Resell-токена (попытка {self._consecutive_auth_failures + 1}/{self.MAX_AUTH_FAILURES})...")

        try:
            s = requests.Session()
            if self._proxy:
                apply_proxy_to_session(s, self._proxy)
            resp = s.post(
                self.RESELL_TOKENS_URL,
                json={"token": {"account_name": self.account_id}},
                headers={"Content-Type": "application/json", "X-Token": self.api_key},
                timeout=15,
            )
            s.close()
            if resp.status_code in (200, 201):
                data = resp.json()
                new_token = data.get("token", {}).get("id", "")
                if new_token:
                    self._token = new_token
                    self._token_expires = time.time() + 23 * 3600
                    self._consecutive_auth_failures = 0
                    log_ok("Selectel: Resell-токен обновлён")
                    return
                raise RuntimeError(f"Нет token.id: {json.dumps(data)[:200]}")
            if resp.status_code == 401:
                self._consecutive_auth_failures += 1
                log_err(f"[SELECTEL] Resell HTTP 401 (попытка {self._consecutive_auth_failures}/{self.MAX_AUTH_FAILURES})")
                if self._consecutive_auth_failures >= self.MAX_AUTH_FAILURES:
                    raise PermissionError(
                        f"Resell: {self.MAX_AUTH_FAILURES} подряд 401 — API-ключ невалиден "
                        f"(account: {self.account_id})"
                    )
                raise RuntimeError("Resell HTTP 401: Unauthorized")
            raise RuntimeError(f"Resell HTTP {resp.status_code}: {resp.text[:300]}")
        except (PermissionError, RuntimeError):
            raise
        except requests.RequestException as e:
            log_err(f"Selectel: ошибка Resell: {e}")
            raise


# ═══════════════════════════════════════════════════════════════════
# SelectelProvider — 1:1 из v11
# ═══════════════════════════════════════════════════════════════════

class SelectelProvider(BaseProvider):
    """Selectel — один аккаунт = один провайдер. VPC Resell API. Логика из v11."""

    name: str = "selectel"

    def __init__(self, cfg: dict, timeout: tuple[int, int] = (10, 30),
                 proxy: Optional[dict] = None) -> None:
        super().__init__(cfg, timeout, proxy)
        self._instance_label = cfg.get("label", "selectel")
        self.batch_size = 1

    def init_session(self) -> None:
        cfg = self.cfg
        self._base = cfg.get("base_url",
                    cfg.get("api_base", "https://api.selectel.ru/vpc/resell/")).rstrip("/")
        self.batch_size = int(cfg.get("batch_size", 2))
        self._project_id = cfg.get("project_id", "")

        self.token_mgr = KeystoneTokenManager(
            account_id=cfg.get("account_id", ""),
            username=cfg.get("username", ""),
            password=cfg.get("password", ""),
            api_key=cfg.get("api_key", ""),
            project_name=cfg.get("project_name", ""),
            project_id=self._project_id,
            proxy=self.proxy,
        )

        static_token = cfg.get("token", "")
        if self.token_mgr.mode == "static":
            if static_token and static_token != "auto":
                self.token_mgr.set_static_token(static_token)
                log_info(f"Selectel [{self._instance_label}]: статический токен")
            else:
                raise RuntimeError("Selectel: нет credentials и нет статического токена")
        else:
            try:
                self.token_mgr.get_token()
                log_ok(f"Selectel [{self._instance_label}]: авто-обновление ({self.token_mgr.mode})")
            except Exception as e:
                if static_token and static_token != "auto":
                    log_warn(f"Selectel [{self._instance_label}]: fallback на статический ({e})")
                    self.token_mgr.set_static_token(static_token)
                else:
                    raise

        self._rebuild_session()

    @property
    def current_account_label(self) -> str:
        return self._instance_label

    def get_regions(self) -> list[str]:
        return self.cfg.get("regions", ["ru-1", "ru-3", "ru-7"])

    def _rebuild_session(self):
        token = self.token_mgr.get_token()
        if self.session:
            self.session.headers["X-Auth-Token"] = token
        else:
            self.session = make_session(token=token, auth_header="X-Auth-Token", proxy=self.proxy)

    def _refresh_and_retry(self):
        if self.token_mgr.mode == "static":
            raise PermissionError("Токен истёк, авто-обновление не настроено")
        log_info(f"Selectel [{self._instance_label}]: токен истёк, обновляю...")
        self.token_mgr.get_token(force_refresh=True)
        self._rebuild_session()

    def create_ip(self, region: str) -> ProviderResult:
        url = f"{self._base}/v2/floatingips/projects/{self._project_id}"
        payload = {"floatingips": [{"quantity": 1, "region": region}]}

        for attempt in range(2):
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 401 and attempt == 0:
                self._refresh_and_retry()
                continue
            if resp.status_code == 429:
                raise RuntimeError("Rate limit (429)")
            if resp.status_code == 409:
                raise RuntimeError(f"Конфликт/квота (409): {resp.text[:300]}")
            if resp.status_code == 403:
                raise PermissionError(f"Нет прав: {resp.text[:200]}")
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")

            fips = resp.json().get("floatingips", [])
            if not fips:
                raise RuntimeError("Пустой ответ")
            fip = fips[0]
            return ProviderResult(
                ip=fip.get("floating_ip_address", ""),
                resource_id=fip.get("id", ""),
                region=region, raw=fip,
            )
        raise RuntimeError("Не удалось после обновления токена")

    def create_ip_batch(self, region: str, quantity: int) -> list[ProviderResult]:
        url = f"{self._base}/v2/floatingips/projects/{self._project_id}"
        payload = {"floatingips": [{"quantity": quantity, "region": region}]}

        for attempt in range(2):
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 401 and attempt == 0:
                self._refresh_and_retry()
                continue
            if resp.status_code == 429:
                raise RuntimeError("Rate limit (429)")
            if resp.status_code == 409:
                raise RuntimeError(f"Конфликт/квота (409): {resp.text[:300]}")
            if resp.status_code == 403:
                raise PermissionError(f"Нет прав: {resp.text[:200]}")
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")

            fips = resp.json().get("floatingips", [])
            results = []
            for fip in fips:
                ip = fip.get("floating_ip_address", "")
                rid = fip.get("id", "")
                if ip and rid:
                    results.append(ProviderResult(ip=ip, resource_id=rid, region=region, raw=fip))
            if not results:
                raise RuntimeError(f"Batch: 0 IP создано из {quantity} (возможно квота)")
            return results
        raise RuntimeError("Не удалось после обновления токена")

    def delete_ip(self, resource_id: str) -> None:
        """Синхронное удаление в основном потоке (как в v11)."""
        url = f"{self._base}/v2/floatingips/{resource_id}"
        for attempt in range(2):
            resp = self.session.delete(url, timeout=self.timeout)
            if resp.status_code == 401 and attempt == 0:
                self._refresh_and_retry()
                continue
            if resp.status_code not in (200, 204):
                raise RuntimeError(f"Delete HTTP {resp.status_code}")
            return

    # Регионы Neutron API для list floating IPs
    NEUTRON_REGIONS = ["ru-1", "ru-2", "ru-3", "ru-7", "ru-8", "ru-9"]

    def list_ips(self) -> list[ProviderResult]:
        """Получить все floating IP через OpenStack Neutron API.

        Resell API не поддерживает GET list — используем Neutron endpoint
        из Keystone service catalog: https://{region}.cloud.api.selcloud.ru/network/v2.0/floatingips
        """
        all_ips: list[ProviderResult] = []
        regions_to_check = self.get_regions() or self.NEUTRON_REGIONS

        for region in regions_to_check:
            neutron_url = f"https://{region}.cloud.api.selcloud.ru/network/v2.0/floatingips"
            try:
                resp = self.session.get(neutron_url, timeout=15)
                if resp.status_code == 401:
                    self._refresh_and_retry()
                    resp = self.session.get(neutron_url, timeout=15)
                if resp.status_code != 200:
                    continue
                fips = resp.json().get("floatingips", [])
                for f in fips:
                    ip = f.get("floating_ip_address", "")
                    rid = f.get("id", "")
                    if ip and rid:
                        all_ips.append(ProviderResult(
                            ip=ip, resource_id=rid,
                            region=f.get("region", region), raw=f,
                        ))
            except Exception as exc:
                log_debug(f"[Selectel] list_ips Neutron {region}: {exc}")
                continue

        if all_ips:
            log_info(f"[Selectel] [{self._instance_label}] list_ips: {len(all_ips)} IP через Neutron")
        return all_ips
