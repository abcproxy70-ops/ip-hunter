"""Reg.ru Cloud VPS provider — GraphQL API с эмуляцией браузера.

Упрощённая авторизация: ТОЛЬКО через cookies (SESSION_ID).
Пользователь логинится в браузере, копирует cookies, вставляет в конфиг.
JWT обновляется автоматически через POST /refresh с SESSION_ID.
Никакого логина по паролю — нет проблем с капчей.
"""

import base64
import json
import random
import re
import threading
import time
from typing import Optional

import requests

from ip_hunter.logger import log_debug, log_err, log_info, log_ok, log_warn
from ip_hunter.providers.base import BaseProvider, DailyLimitError, ProviderResult
from ip_hunter.proxy import apply_proxy_to_session
from ip_hunter.session import make_session

# ── Константы ──
GRAPHQL_URL = "https://cloudvps-graphql-server.svc.reg.ru/api"
ORIGIN = "https://cloud.reg.ru"
REFERER = "https://cloud.reg.ru/"
REFRESH_URL = "https://login.reg.ru/refresh"
IP_POLL_TIMEOUT = 120
IP_POLL_INTERVAL = 3
HUMAN_DELAY_MIN = 0.2
HUMAN_DELAY_MAX = 0.8
MUTATION_DELAY_MIN = 0.5
MUTATION_DELAY_MAX = 1.5

# ── Браузерные fingerprints ──
_REGRU_FINGERPRINTS = [
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
    },
    {
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Linux"',
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "sec_ch_ua": "", "sec_ch_ua_mobile": "", "sec_ch_ua_platform": "",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
        "sec_ch_ua": "", "sec_ch_ua_mobile": "", "sec_ch_ua_platform": "",
    },
]

# ── Случайные имена серверов ──
_ADJECTIVES = ["Red", "Blue", "Green", "Purple", "Golden", "Silver", "Dark", "Bright",
    "Swift", "Calm", "Bold", "Wild", "Iron", "Copper", "Neon", "Frozen"]
_NOUNS = ["Falcon", "Phoenix", "Panther", "Dragon", "Vortex", "Nebula", "Prism",
    "Quasar", "Titan", "Comet", "Spark", "Pulse", "Storm", "Flare"]

# ── GraphQL операции ──
CREATE_SERVER_MUTATION = """
mutation createServer(
  $name: String!, $region: String!, $image: String!, $plan: String!,
  $sshKey: String!, $enableBackups: Boolean!, $enableFloatingIp: Boolean!,
  $promocode: String!, $volumeIds: [Int!]!, $protectedIPPlan: String!,
  $commercialSoftwarePlan: String
) {
  server {
    create(params: {
      name: $name, region: $region, image: $image, plan: $plan,
      sshKey: $sshKey, enableBackups: $enableBackups,
      enableFloatingIp: $enableFloatingIp, promocode: $promocode,
      volumeIds: $volumeIds, protectedIPPlan: $protectedIPPlan,
      commercialSoftwarePlan: $commercialSoftwarePlan
    }) { __typename ... on Server { id name status ipv4 } }
  }
}
""".strip()

SERVER_QUERY = """
query server($serverId: Int!) {
  server(serverId: $serverId) {
    __typename ... on Server { id name ipv4 status floatingIPs { address } }
  }
}
""".strip()

REMOVE_SERVER_MUTATION = """
mutation removeServer($serverId: Int!, $releaseFloatingIPs: [Int!]!, $releaseVolumes: [Int!]!) {
  server {
    remove(params: { serverId: $serverId, releaseFloatingIPs: $releaseFloatingIPs,
      releaseVolumes: $releaseVolumes
    }) { __typename ... on Server { id status } }
  }
}
""".strip()

SERVERS_LIST_QUERY = """
query serverList($page: Int!) {
  serverList(page: $page) {
    __typename ... on ServerList { items { id name status } meta { total lastPage } }
  }
}
""".strip()


def _random_server_name() -> str:
    return f"{random.choice(_ADJECTIVES)} {random.choice(_NOUNS)} {random.randint(100, 999)}"


def _parse_jwt_expiry(jwt_token: str) -> float:
    try:
        parts = jwt_token.split(".")
        if len(parts) < 2:
            return 0
        payload_b64 = parts[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return float(payload.get("exp", 0))
    except Exception:
        return 0


class RegruProvider(BaseProvider):
    """
    Reg.ru — GraphQL API cloud.reg.ru.
    Авторизация ТОЛЬКО через cookies (SESSION_ID → refresh → JWT).
    Пользователь логинится в браузере, копирует cookies.
    """
    name: str = "regru"

    def __init__(self, cfg: dict, timeout: tuple[int, int] = (10, 30),
                 proxy: Optional[dict] = None) -> None:
        super().__init__(cfg, timeout, proxy)
        self._instance_label = cfg.get("label", "regru")
        self._service_id = str(cfg.get("service_id", ""))
        self._region = cfg.get("region", "openstack-msk1")
        self._image = cfg.get("image", "ubuntu-24-04-amd64")
        self._plan = cfg.get("plan", "c1-m1-d10-hp")

        self._fingerprint: dict = {}
        self._request_count = 0
        self._jwt: str = ""
        self._jwt_expires: float = 0
        self._session_id: str = ""
        self._cookies: dict = {}
        self._jwt_lock = threading.Lock()

    @property
    def current_account_label(self) -> str:
        return self._instance_label

    @property
    def _lp(self) -> str:
        return f"Reg.ru[{self._instance_label}]"

    def get_regions(self) -> list[str]:
        return self.cfg.get("regions", [self._region])

    # ── Fingerprint и browser headers ──

    def _pick_fingerprint(self) -> dict:
        return random.choice(_REGRU_FINGERPRINTS)

    def _build_browser_headers(self) -> dict:
        fp = self._fingerprint
        is_chromium = "Chrome" in fp["ua"] and "Firefox" not in fp["ua"] and "Safari/605" not in fp["ua"]

        headers = {
            "User-Agent": fp["ua"],
            "Accept": "*/*",
            "Accept-Language": random.choice([
                "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                "ru,en-US;q=0.9,en;q=0.8",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Origin": ORIGIN,
            "Referer": REFERER,
            "Connection": "keep-alive",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        if is_chromium and fp.get("sec_ch_ua"):
            headers["Sec-Ch-Ua"] = fp["sec_ch_ua"]
            headers["Sec-Ch-Ua-Mobile"] = fp.get("sec_ch_ua_mobile", "?0")
            headers["Sec-Ch-Ua-Platform"] = fp.get("sec_ch_ua_platform", '"Windows"')
        return headers

    def _human_delay(self, is_mutation: bool = False):
        if is_mutation:
            time.sleep(random.uniform(MUTATION_DELAY_MIN, MUTATION_DELAY_MAX))
        else:
            time.sleep(random.uniform(HUMAN_DELAY_MIN, HUMAN_DELAY_MAX))

    def _maybe_rotate_fingerprint(self):
        self._request_count += 1
        if self._request_count >= random.randint(30, 60):
            self._fingerprint = self._pick_fingerprint()
            new_headers = self._build_browser_headers()
            for key in list(self.session.headers.keys()):
                if key.lower() not in ("authorization", "service-id"):
                    del self.session.headers[key]
            self.session.headers.update(new_headers)
            self._request_count = 0

    # ── Cookie sync ──

    def _sync_cookies_to_session(self):
        if not self.session:
            return
        for k, v in self._cookies.items():
            self.session.cookies.set(k, v, domain=".reg.ru")
        if self._jwt:
            self.session.cookies.set("JWT", self._jwt, domain=".reg.ru")
            self.session.cookies.set("jwt", self._jwt, domain=".reg.ru")

    # ── JWT через refresh (единственный способ авторизации) ──

    def _extract_jwt_from_response(self, resp) -> tuple[str, str]:
        """Извлечь JWT и JWT_REFRESH из Set-Cookie. Case-insensitive."""
        new_jwt = ""
        new_refresh = ""
        for cookie in resp.cookies:
            name_upper = cookie.name.upper()
            if name_upper == "JWT" and "." in cookie.value and len(cookie.value) > 50:
                new_jwt = cookie.value
            elif name_upper == "JWT_REFRESH" and len(cookie.value) > 10:
                new_refresh = cookie.value
        if not new_jwt or not new_refresh:
            raw_sc_list = []
            try:
                raw_sc_list = resp.raw._original_response.headers.get_all("Set-Cookie") or []
            except Exception:
                pass
            if not raw_sc_list:
                try:
                    raw_sc_list = resp.raw.headers.getlist("Set-Cookie") or []
                except Exception:
                    pass
            for sc_line in raw_sc_list:
                if not new_jwt:
                    for prefix in ("JWT=", "jwt="):
                        if prefix in sc_line and "REFRESH" not in sc_line.upper():
                            try:
                                new_jwt = sc_line.split(prefix)[1].split(";")[0]
                            except Exception:
                                pass
                if not new_refresh:
                    for prefix in ("JWT_REFRESH=", "jwt_refresh="):
                        if prefix.lower() in sc_line.lower():
                            try:
                                idx = sc_line.lower().index(prefix.lower())
                                new_refresh = sc_line[idx+len(prefix):].split(";")[0]
                            except Exception:
                                pass
        return new_jwt, new_refresh

    def _refresh_jwt(self):
        """Обновление JWT через POST /refresh с SESSION_ID."""
        with self._jwt_lock:
            self._do_refresh_jwt()

    def _do_refresh_jwt(self):
        """POST /refresh — единственный способ получить JWT. Под _jwt_lock!"""
        if time.time() < self._jwt_expires - 30:
            return

        log_debug(f"{self._lp}: обновление JWT через refresh...")

        # Собираем cookie header
        cookie_parts = []
        for k, v in self._cookies.items():
            if k.upper() != "JWT":
                cookie_parts.append(f"{k}={v}")
        if self._jwt:
            cookie_parts.append(f"JWT={self._jwt}")
        cookie_header = "; ".join(cookie_parts)

        csrf = self._cookies.get("csrftoken", "")
        headers = {
            "User-Agent": self._fingerprint.get("ua", ""),
            "Accept": "application/json, text/plain, */*",
            "Content-Length": "0",
            "Origin": ORIGIN,
            "Referer": REFERER,
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Cookie": cookie_header,
        }
        if csrf:
            headers["x-csrf-token"] = csrf

        # login.reg.ru — ВСЕГДА direct (без SOCKS прокси)
        try:
            s = requests.Session()
            resp = s.post(REFRESH_URL, headers=headers, timeout=15)

            if resp.status_code != 200:
                log_warn(f"{self._lp}: refresh HTTP {resp.status_code}: {resp.text[:200]}")
                s.close()
                return

            new_jwt, new_refresh = self._extract_jwt_from_response(resp)
            s.close()

            if new_jwt and "." in new_jwt:
                self._jwt = new_jwt
                self._jwt_expires = _parse_jwt_expiry(new_jwt)
                ttl = int(self._jwt_expires - time.time())
                if new_refresh and new_refresh != '""' and len(new_refresh) > 10:
                    self._cookies["JWT_REFRESH"] = new_refresh
                log_ok(f"{self._lp}: JWT обновлён (TTL: {ttl}с)")
                self._sync_cookies_to_session()
                return
            else:
                log_warn(f"{self._lp}: refresh не вернул JWT")
                log_debug(f"{self._lp}: cookies: {dict(resp.cookies)}")
                try:
                    log_debug(f"{self._lp}: Set-Cookie: {resp.headers.get('Set-Cookie', '')[:300]}")
                except Exception:
                    pass

        except Exception as e:
            log_warn(f"{self._lp}: refresh ошибка: {e}")

    def _ensure_jwt_valid(self):
        with self._jwt_lock:
            if time.time() > self._jwt_expires - 60:
                self._do_refresh_jwt()
                if time.time() > self._jwt_expires - 60:
                    raise RuntimeError(
                        f"{self._lp}: JWT протух и refresh не помог. "
                        f"Обновите cookies: залогиньтесь на cloud.reg.ru → DevTools → "
                        f"Application → Cookies → скопируйте SESSION_ID и JWT"
                    )

    # ── init_session ──

    def init_session(self) -> None:
        if not self._service_id:
            raise RuntimeError("Нет service_id для Reg.ru")

        # Парсим cookies из конфига
        cookies_str = self.cfg.get("token", "")
        if not cookies_str:
            raise RuntimeError(
                f"{self._lp}: нет cookies. Залогиньтесь на cloud.reg.ru в браузере, "
                f"DevTools (F12) → Application → Cookies → cloud.reg.ru → "
                f"скопируйте: SESSION_ID=...; JWT=... и вставьте в --setup"
            )

        parsed_cookies = {}
        if "=" in cookies_str and ";" in cookies_str:
            for part in cookies_str.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    parsed_cookies[k.strip()] = v.strip()
        elif cookies_str.startswith("eyJ"):
            parsed_cookies["JWT"] = cookies_str
        elif len(cookies_str) > 10:
            parsed_cookies["SESSION_ID"] = cookies_str

        self._session_id = parsed_cookies.get("SESSION_ID", "")
        self._jwt = parsed_cookies.get("JWT", parsed_cookies.get("jwt", ""))
        self._cookies = parsed_cookies

        if not self._session_id and not self._jwt:
            raise RuntimeError(
                f"{self._lp}: в cookies нет ни SESSION_ID ни JWT. "
                f"Вставьте полную строку: SESSION_ID=...; JWT=..."
            )

        if self._jwt:
            self._jwt_expires = _parse_jwt_expiry(self._jwt)
            ttl = max(0, int(self._jwt_expires - time.time()))
            if ttl > 0:
                log_info(f"{self._lp}: JWT из cookies валиден (TTL: {ttl}с)")
            else:
                log_info(f"{self._lp}: JWT протух, обновлю через refresh...")
                self._jwt = ""
                self._jwt_expires = 0

        # Fingerprint и сессия
        self._fingerprint = self._pick_fingerprint()
        browser_headers = self._build_browser_headers()

        self.session = make_session(token="", auth_header="X-Auth-Token", proxy=self.proxy)
        self.session.headers.update(browser_headers)
        self.session.headers["service-id"] = self._service_id
        self.session.headers.pop("Authorization", None)
        self.session.headers.pop("X-Auth-Token", None)

        self._sync_cookies_to_session()

        # Обновляем JWT если нужно
        if not self._jwt or time.time() > self._jwt_expires - 60:
            self._refresh_jwt()

        if not self._jwt or time.time() > self._jwt_expires:
            raise RuntimeError(
                f"{self._lp}: JWT не получен. SESSION_ID может быть протухшим. "
                f"Залогиньтесь заново на cloud.reg.ru и обновите cookies."
            )

        # Проверка API
        log_debug(f"{self._lp}: проверка GraphQL API...")
        self._human_delay()
        try:
            test_resp = self.session.post(
                GRAPHQL_URL,
                json={"operationName": "server", "variables": {"serverId": 0}, "query": SERVER_QUERY},
                timeout=self.timeout,
            )
            if test_resp.status_code == 401:
                raise PermissionError("Cookies невалидны (401)")
            if test_resp.status_code == 403:
                raise PermissionError("Доступ запрещён (403)")
            try:
                body = test_resp.json()
                srv = body.get("data", {}).get("server", {})
                if isinstance(srv, dict) and srv.get("__typename") == "Unauthorized":
                    raise PermissionError("API Unauthorized — обновите cookies")
            except (json.JSONDecodeError, AttributeError):
                pass
            log_ok(f"{self._lp}: GraphQL API доступен")
        except requests.RequestException as e:
            log_warn(f"{self._lp}: API недоступен ({e}) — продолжаю")

    # ── GraphQL ──

    def _graphql(self, operation_name: str, query: str, variables: dict,
                 is_mutation: bool = False) -> dict:
        self._ensure_jwt_valid()
        self._human_delay(is_mutation=is_mutation)
        self._maybe_rotate_fingerprint()

        payload = {"operationName": operation_name, "variables": variables, "query": query}

        for attempt in range(2):
            cookie_parts = []
            for k, v in self._cookies.items():
                if k.upper() != "JWT":
                    cookie_parts.append(f"{k}={v}")
            if self._jwt:
                cookie_parts.append(f"JWT={self._jwt}")
            self.session.headers["Cookie"] = "; ".join(cookie_parts)

            resp = self.session.post(GRAPHQL_URL, json=payload, timeout=self.timeout)

            if resp.status_code == 429:
                raise RuntimeError("Rate limit (429)")
            if resp.status_code == 401:
                if attempt == 0 and self._session_id:
                    log_debug(f"{self._lp}: 401, обновляю JWT...")
                    self._refresh_jwt()
                    continue
                raise PermissionError("Cookies невалидны (401)")
            if resp.status_code == 403:
                raise PermissionError(f"Доступ запрещён (403): {resp.text[:300]}")
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"GraphQL HTTP {resp.status_code}: {resp.text[:400]}")

            body = resp.json()
            if "errors" in body and body["errors"]:
                err_msgs = "; ".join(e.get("message", str(e)) for e in body["errors"])
                raise RuntimeError(f"GraphQL errors: {err_msgs}")

            data = body.get("data", {})
            data_str = json.dumps(data)
            if '"Unauthorized"' in data_str:
                if attempt == 0 and self._session_id:
                    log_debug(f"{self._lp}: Unauthorized, обновляю JWT...")
                    self._refresh_jwt()
                    continue
                raise PermissionError("API Unauthorized — обновите cookies")

            return data

        raise RuntimeError("Не удалось после обновления JWT")

    # ── Server operations ──

    def _create_single_server(self, region: str) -> tuple[int, str]:
        server_name = _random_server_name()
        variables = {
            "name": server_name, "region": region, "image": self._image,
            "plan": self._plan, "sshKey": "", "enableBackups": False,
            "enableFloatingIp": True, "promocode": "", "volumeIds": [],
            "protectedIPPlan": "", "commercialSoftwarePlan": None,
        }
        data = self._graphql("createServer", CREATE_SERVER_MUTATION, variables, is_mutation=True)
        create_result = data.get("server", {}).get("create", {})
        typename = create_result.get("__typename", "")
        if typename == "ServerLimitReached":
            raise RuntimeError("ServerLimitReached — лимит серверов")
        if create_result.get("message") and not create_result.get("id"):
            err_msg = create_result.get("message", str(create_result))
            if "лимит" in err_msg.lower() or "limit" in err_msg.lower():
                raise DailyLimitError(f"Reg.ru: {err_msg}")
            if "баланс" in err_msg.lower() or "balance" in err_msg.lower():
                raise PermissionError(f"Reg.ru: {err_msg}")
            raise RuntimeError(f"createServer: {err_msg}")
        server_id = create_result.get("id")
        if not server_id:
            raise RuntimeError(f"createServer: нет id: {json.dumps(create_result)[:300]}")
        return int(server_id), server_name

    def _poll_server_ip(self, server_id: int) -> Optional[str]:
        data = self._graphql("server", SERVER_QUERY, {"serverId": server_id})
        server = data.get("server", {})
        if server.get("message") and not server.get("id"):
            raise RuntimeError(f"Ошибка сервера #{server_id}: {server.get('message')}")
        status = server.get("status", "")
        if status in ("error", "failed", "deleting", "deleted"):
            raise RuntimeError(f"Сервер #{server_id} в статусе '{status}'")
        for fip in server.get("floatingIPs", []):
            addr = fip.get("address", "")
            if addr and addr != "0.0.0.0":
                return addr
        if status == "active":
            ipv4 = server.get("ipv4", "")
            if ipv4 and ipv4 != "0.0.0.0":
                return ipv4
        return None

    def create_ip(self, region: str) -> ProviderResult:
        from ip_hunter.worker import is_shutdown
        for create_attempt in range(5):
            try:
                server_id, server_name = self._create_single_server(region)
                break
            except RuntimeError as e:
                if "ServerLimitReached" in str(e):
                    if create_attempt == 0:
                        log_info(f"{self._lp}: лимит серверов, очистка зомби...")
                        self.cleanup_zombie_servers()
                        time.sleep(5.0)
                    else:
                        time.sleep(10 + create_attempt * 5)
                    continue
                raise
        else:
            raise RuntimeError("ServerLimitReached — 5 попыток")

        log_info(f"{self._lp}: сервер #{server_id} '{server_name}' создаётся...")
        deadline = time.time() + IP_POLL_TIMEOUT
        while time.time() < deadline:
            if is_shutdown():
                try:
                    self._remove_server(server_id)
                except Exception:
                    pass
                raise RuntimeError("Остановлено пользователем")
            try:
                ip = self._poll_server_ip(server_id)
                if ip:
                    return ProviderResult(ip=ip, resource_id=str(server_id), region=region)
            except RuntimeError:
                try:
                    self._remove_server(server_id)
                except Exception:
                    pass
                raise
            time.sleep(IP_POLL_INTERVAL + random.uniform(-0.5, 1.0))

        try:
            self._remove_server(server_id)
        except Exception:
            pass
        raise RuntimeError(f"Таймаут {IP_POLL_TIMEOUT}с: сервер #{server_id} не получил IP")

    def _remove_server(self, server_id: int):
        variables = {"serverId": server_id, "releaseFloatingIPs": [], "releaseVolumes": []}
        data = self._graphql("removeServer", REMOVE_SERVER_MUTATION, variables, is_mutation=True)
        remove_result = data.get("server", {}).get("remove", {})
        if remove_result.get("message") and not remove_result.get("id"):
            raise RuntimeError(f"removeServer: {remove_result['message']}")
        for _ in range(12):
            time.sleep(2.0)
            try:
                poll_data = self._graphql("server", SERVER_QUERY, {"serverId": server_id})
                srv = poll_data.get("server", {})
                status = srv.get("status", "")
                typename = srv.get("__typename", "")
                if status in ("deleted", "") or typename in ("NotFound", "ServerNotFound"):
                    break
            except Exception:
                break
        log_debug(f"{self._lp}: сервер #{server_id} удалён")

    def delete_ip(self, resource_id: str):
        try:
            self._remove_server(int(resource_id))
        except (ValueError, TypeError):
            log_warn(f"{self._lp}: невалидный resource_id: {resource_id}")

    def cleanup_zombie_servers(self):
        try:
            all_items = []
            page = 1
            while True:
                data = self._graphql("serverList", SERVERS_LIST_QUERY, {"page": page})
                servers_data = data.get("serverList", {})
                items = servers_data.get("items", []) or []
                if items:
                    all_items.extend(items)
                meta = servers_data.get("meta", {})
                if page >= meta.get("lastPage", 1):
                    break
                page += 1
            alive = [s for s in all_items if s.get("status") not in ("deleting", "deleted")]
            if not alive:
                return
            log_info(f"{self._lp}: найдено {len(alive)} серверов, удаляю...")
            for srv in alive:
                sid = srv.get("id")
                if sid:
                    try:
                        self._remove_server(int(sid))
                    except Exception as e:
                        log_debug(f"{self._lp}: не удалось удалить #{sid}: {e}")
            log_ok(f"{self._lp}: очистка завершена")
        except Exception as e:
            log_debug(f"{self._lp}: ошибка получения списка: {e}")

    def list_ips(self) -> list[ProviderResult]:
        return []
