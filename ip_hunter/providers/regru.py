"""Reg.ru Cloud VPS provider — GraphQL API с эмуляцией браузера.

Логика 1:1 из v11 монолита:
- Полный логин: GET www.reg.ru → CSRF → POST authenticate → POST refresh → JWT
- Browser fingerprints (Chrome/Firefox/Edge/Safari) с Sec-Ch-Ua
- GraphQL: createServer → poll floatingIP → проверка подсети → removeServer
- JWT авто-обновление через refresh с fallback на полный ре-логин
- Captcha через 2captcha API
"""

import base64
import json
import random
import re
import secrets
import threading
import time
from typing import Optional

import requests

from ip_hunter.captcha import detect_captcha, solve_captcha
from ip_hunter.logger import log_debug, log_err, log_info, log_ok, log_warn
from ip_hunter.providers.base import BaseProvider, DailyLimitError, ProviderResult
from ip_hunter.proxy import apply_proxy_to_session
from ip_hunter.session import make_session

# ── Константы ──
GRAPHQL_URL = "https://cloudvps-graphql-server.svc.reg.ru/api"
ORIGIN = "https://cloud.reg.ru"
REFERER = "https://cloud.reg.ru/"
AUTHENTICATE_URL = "https://login.reg.ru/authenticate"
REFRESH_URL = "https://login.reg.ru/refresh"
IP_POLL_TIMEOUT = 120
IP_POLL_INTERVAL = 3
HUMAN_DELAY_MIN = 0.2
HUMAN_DELAY_MAX = 0.8
MUTATION_DELAY_MIN = 0.5
MUTATION_DELAY_MAX = 1.5
MAX_LOGIN_FAILURES = 3

# ── Браузерные fingerprints из v11 ──
_REGRU_FINGERPRINTS = [
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
        "platform": "MacIntel",
    },
    {
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Linux"',
        "platform": "Linux x86_64",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="145", "Not-A.Brand";v="24", "Google Chrome";v="145"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
        "sec_ch_ua": '"Chromium";v="146", "Microsoft Edge";v="146", "Not-A.Brand";v="24"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "platform": "Win32",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="145", "Not-A.Brand";v="24", "Google Chrome";v="145"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
        "platform": "MacIntel",
    },
    {
        "ua": "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "platform": "Linux x86_64",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
        "sec_ch_ua": "",
        "sec_ch_ua_mobile": "",
        "sec_ch_ua_platform": "",
        "platform": "MacIntel",
    },
    {
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0",
        "sec_ch_ua": '"Chromium";v="146", "Microsoft Edge";v="146", "Not-A.Brand";v="24"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
        "platform": "MacIntel",
    },
]

# ── Случайные имена серверов ──
_ADJECTIVES = [
    "Red", "Blue", "Green", "Purple", "Golden", "Silver", "Dark", "Bright",
    "Swift", "Calm", "Bold", "Wild", "Iron", "Copper", "Neon", "Frozen",
    "Amber", "Violet", "Coral", "Lunar", "Solar", "Crimson", "Azure", "Jade",
]
_NOUNS = [
    "Falcon", "Phoenix", "Panther", "Dragon", "Vortex", "Nebula", "Prism",
    "Quasar", "Titan", "Comet", "Spark", "Pulse", "Storm", "Flare", "Orbit",
    "Glacier", "Fluorum", "Helium", "Photon", "Neutron", "Kernel", "Matrix",
]

# ── GraphQL операции (полные, читаемые, как в v11) ──
CREATE_SERVER_MUTATION = """
mutation createServer(
  $name: String!,
  $region: String!,
  $image: String!,
  $plan: String!,
  $sshKey: String!,
  $enableBackups: Boolean!,
  $enableFloatingIp: Boolean!,
  $promocode: String!,
  $volumeIds: [Int!]!,
  $protectedIPPlan: String!,
  $commercialSoftwarePlan: String
) {
  server {
    create(params: {
      name: $name,
      region: $region,
      image: $image,
      plan: $plan,
      sshKey: $sshKey,
      enableBackups: $enableBackups,
      enableFloatingIp: $enableFloatingIp,
      promocode: $promocode,
      volumeIds: $volumeIds,
      protectedIPPlan: $protectedIPPlan,
      commercialSoftwarePlan: $commercialSoftwarePlan
    }) {
      __typename
      ... on Server {
        id
        name
        status
        ipv4
      }
    }
  }
}
""".strip()

SERVER_QUERY = """
query server($serverId: Int!) {
  server(serverId: $serverId) {
    __typename
    ... on Server {
      id
      name
      ipv4
      status
      floatingIPs {
        address
      }
    }
  }
}
""".strip()

REMOVE_SERVER_MUTATION = """
mutation removeServer(
  $serverId: Int!,
  $releaseFloatingIPs: [Int!]!,
  $releaseVolumes: [Int!]!
) {
  server {
    remove(params: {
      serverId: $serverId,
      releaseFloatingIPs: $releaseFloatingIPs,
      releaseVolumes: $releaseVolumes
    }) {
      __typename
      ... on Server {
        id
        status
      }
    }
  }
}
""".strip()

SERVERS_LIST_QUERY = """
query serverList($page: Int!) {
  serverList(page: $page) {
    __typename
    ... on ServerList {
      items {
        id
        name
        status
      }
      meta {
        total
        lastPage
      }
    }
  }
}
""".strip()


def _random_server_name() -> str:
    return f"{random.choice(_ADJECTIVES)} {random.choice(_NOUNS)} {random.randint(100, 999)}"


def _parse_jwt_expiry(jwt_token: str) -> float:
    """Извлекает exp из JWT payload (без верификации подписи)."""
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


# ═══════════════════════════════════════════════════════════════════
# RegruProvider — 1:1 из v11 монолита
# ═══════════════════════════════════════════════════════════════════

class RegruProvider(BaseProvider):
    """
    Reg.ru — GraphQL API панели cloud.reg.ru с эмуляцией браузера.
    Логика ПОЛНОСТЬЮ из v11.
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
        self._login = cfg.get("login", "")
        self._password = cfg.get("password", "")
        self._captcha_api_key = cfg.get("captcha_api_key", "")
        self._has_credentials = bool(self._login and self._password)

        self._fingerprint: dict = {}
        self._request_count = 0
        self._jwt: str = ""
        self._jwt_expires: float = 0
        self._session_id: str = ""
        self._cookies: dict = {}
        self._jwt_lock = threading.Lock()
        self._consecutive_login_failures: int = 0

    @property
    def current_account_label(self) -> str:
        return self._instance_label

    @property
    def _lp(self) -> str:
        return f"Reg.ru[{self._instance_label}]"

    def get_regions(self) -> list[str]:
        return self.cfg.get("regions", [self._region])

    # ── Fingerprint и browser headers (из v11) ──

    def _pick_fingerprint(self) -> dict:
        return random.choice(_REGRU_FINGERPRINTS)

    def _build_browser_headers(self) -> dict:
        fp = self._fingerprint
        is_firefox = "Firefox" in fp["ua"]
        is_safari = "Safari" in fp["ua"] and "Chrome" not in fp["ua"]
        is_chromium = not is_firefox and not is_safari

        headers = {
            "User-Agent": fp["ua"],
            "Accept": "*/*",
            "Accept-Language": random.choice([
                "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
                "ru,en-US;q=0.9,en;q=0.8",
                "ru-RU,ru;q=0.9,en;q=0.8",
                "en-US,en;q=0.9,ru;q=0.8",
                "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3",
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

        if random.random() < 0.3:
            headers["DNT"] = "1"

        return headers

    def _human_delay(self, is_mutation: bool = False):
        if is_mutation:
            delay = random.uniform(MUTATION_DELAY_MIN, MUTATION_DELAY_MAX)
        else:
            delay = random.uniform(HUMAN_DELAY_MIN, HUMAN_DELAY_MAX)
        time.sleep(delay)

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

    # ── JWT management (из v11) ──

    def _sync_cookies_to_session(self):
        """Синхронизировать все self._cookies в self.session.cookies (оба домена)."""
        if not self.session:
            return
        for k, v in self._cookies.items():
            self.session.cookies.set(k, v, domain=".reg.ru")
            self.session.cookies.set(k, v, domain="login.reg.ru")
        # Дублируем JWT как jwt (строчные) — reg.ru может ожидать оба варианта
        if self._jwt:
            self.session.cookies.set("JWT", self._jwt, domain=".reg.ru")
            self.session.cookies.set("jwt", self._jwt, domain=".reg.ru")

    def _refresh_jwt(self):
        """Обновление JWT с блокировкой."""
        with self._jwt_lock:
            self._do_refresh_jwt()

    def _do_refresh_jwt(self):
        """Обновляет JWT через POST /refresh. ВЫЗЫВАТЬ ТОЛЬКО ПОД _jwt_lock!"""
        if time.time() < self._jwt_expires - 30:
            return

        log_debug(f"{self._lp}: обновление JWT...")

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

        # login.reg.ru — direct (без SOCKS прокси)
        try:
            s = requests.Session()
            resp = s.post(REFRESH_URL, headers=headers, timeout=15)

            if resp.status_code != 200:
                log_warn(f"{self._lp}: refresh HTTP {resp.status_code}: {resp.text[:200]}")
                s.close()
            else:
                new_jwt, new_refresh = self._extract_jwt_from_response(resp)
                s.close()

                if new_jwt and "." in new_jwt:
                    self._jwt = new_jwt
                    self._jwt_expires = _parse_jwt_expiry(new_jwt)
                    ttl = int(self._jwt_expires - time.time())

                    if self.session:
                        self.session.cookies.set("JWT", new_jwt, domain=".reg.ru")

                    if new_refresh and new_refresh != '""' and len(new_refresh) > 10:
                        self._cookies["JWT_REFRESH"] = new_refresh

                    log_ok(f"{self._lp}: JWT обновлён (TTL: {ttl}с)")
                    self._sync_cookies_to_session()
                    return
                else:
                    log_warn(f"{self._lp}: refresh не вернул JWT")
                    log_debug(f"{self._lp}: resp.cookies: {dict(resp.cookies)}")
                    try:
                        sc = resp.headers.get("Set-Cookie", "")
                        log_debug(f"{self._lp}: Set-Cookie: {sc[:300]}")
                    except Exception:
                        pass

        except Exception as e:
            log_debug(f"{self._lp}: refresh ошибка: {e}")

        log_info(f"{self._lp}: не удалось обновить JWT через refresh")

        # Fallback: полный ре-логин
        if self._has_credentials:
            log_info(f"{self._lp}: пробую полный ре-логин...")
            self._do_full_login()
        else:
            log_info(f"{self._lp}: нет credentials для ре-логина")

    def _extract_jwt_from_response(self, resp) -> tuple[str, str]:
        """Извлечь JWT и JWT_REFRESH из Set-Cookie. Case-insensitive."""
        new_jwt = ""
        new_refresh = ""

        # Способ 1: resp.cookies (case-insensitive name check)
        for cookie in resp.cookies:
            name_upper = cookie.name.upper()
            if name_upper == "JWT" and "." in cookie.value and len(cookie.value) > 50:
                new_jwt = cookie.value
            elif name_upper == "JWT_REFRESH" and len(cookie.value) > 10:
                new_refresh = cookie.value

        # Способ 2: urllib3 raw response (Set-Cookie headers)
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
                # JWT= (не JWT_REFRESH=)
                if not new_jwt:
                    for prefix in ("JWT=", "jwt="):
                        if prefix in sc_line and "JWT_REFRESH=" not in sc_line and "jwt_refresh=" not in sc_line.lower():
                            try:
                                new_jwt = sc_line.split(prefix)[1].split(";")[0]
                            except Exception:
                                pass
                if not new_refresh:
                    for prefix in ("JWT_REFRESH=", "jwt_refresh="):
                        if prefix in sc_line:
                            try:
                                new_refresh = sc_line.split(prefix)[1].split(";")[0]
                            except Exception:
                                pass

        return new_jwt, new_refresh

    def _do_full_login(self):
        """
        Полная авторизация через POST /authenticate + refresh. Из v11.
        ВЫЗЫВАТЬ ТОЛЬКО ПОД _jwt_lock!
        """
        # ── Шаг 0: Получаем csrftoken если его нет ──
        csrf = self._cookies.get("csrftoken", "")
        if not csrf:
            log_debug(f"{self._lp}: нет csrftoken, пробую получить...")
            csrf_urls = [
                "https://www.reg.ru/",
                "https://cloud.reg.ru/",
                "https://login.reg.ru/",
            ]
            try:
                s_csrf = requests.Session()
                for csrf_url in csrf_urls:
                    try:
                        csrf_resp = s_csrf.get(
                            csrf_url,
                            headers={
                                "User-Agent": self._fingerprint.get("ua", ""),
                                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            },
                            timeout=10,
                            allow_redirects=True,
                        )
                        for cookie in csrf_resp.cookies:
                            self._cookies[cookie.name] = cookie.value
                            if cookie.name == "csrftoken":
                                csrf = cookie.value
                            if cookie.name == "SESSION_ID":
                                self._session_id = cookie.value
                        # Способ 2: парсинг <meta name="_csrf" content="..."> из HTML
                        if not csrf and csrf_resp.text:
                            meta_match = re.search(
                                r'<meta\s+name=["\']_csrf["\'][^>]*content=["\']([^"\']+)',
                                csrf_resp.text
                            )
                            if not meta_match:
                                meta_match = re.search(
                                    r'content=["\']([^"\']+)["\'][^>]*name=["\']_csrf["\']',
                                    csrf_resp.text
                                )
                            if meta_match:
                                csrf = meta_match.group(1)
                                self._cookies["csrftoken"] = csrf
                                log_debug(f"{self._lp}: csrftoken из <meta>: {csrf[:12]}...")
                        if csrf:
                            log_debug(f"{self._lp}: csrftoken от {csrf_url}: {csrf[:12]}...")
                            break
                    except Exception:
                        continue
                s_csrf.close()
            except Exception as e:
                log_debug(f"{self._lp}: ошибка получения csrftoken: {e}")

            # Fallback: генерируем csrftoken сами
            if not csrf:
                csrf = secrets.token_hex(32)
                self._cookies["csrftoken"] = csrf
                log_debug(f"{self._lp}: csrftoken сгенерирован: {csrf[:12]}...")

        # ── Шаг 1: Authenticate ──
        cookie_parts = [f"{k}={v}" for k, v in self._cookies.items()]
        cookie_header = "; ".join(cookie_parts)

        auth_headers = {
            "User-Agent": self._fingerprint.get("ua", ""),
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": ORIGIN,
            "Referer": REFERER,
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Cookie": cookie_header,
        }
        if csrf:
            auth_headers["x-csrf-token"] = csrf

        auth_payload = {"login": self._login, "password": self._password}

        try:
            s = requests.Session()
            resp = s.post(AUTHENTICATE_URL, json=auth_payload,
                          headers=auth_headers, timeout=15)

            if resp.status_code == 401:
                self._consecutive_login_failures += 1
                log_err(f"{self._lp}: authenticate HTTP 401 (попытка {self._consecutive_login_failures}/{MAX_LOGIN_FAILURES})")
                s.close()
                if self._consecutive_login_failures >= MAX_LOGIN_FAILURES:
                    raise PermissionError(
                        f"Reg.ru: {MAX_LOGIN_FAILURES} подряд неудач логина — "
                        f"credentials невалидны (login: {self._login})"
                    )
                return

            if resp.status_code == 400:
                resp_text = resp.text[:500]
                if "CSRF_CHECK_FAILED" in resp_text:
                    self._cookies.pop("csrftoken", None)
                    log_warn(f"{self._lp}: CSRF_CHECK_FAILED — csrftoken сброшен")
                else:
                    log_err(f"{self._lp}: authenticate HTTP 400: {resp_text}")
                s.close()
                return

            if resp.status_code != 200:
                log_err(f"{self._lp}: authenticate HTTP {resp.status_code}: {resp.text[:300]}")
                s.close()
                return

            body = resp.json()

            # Captcha handling
            if body.get("status") == "need_captcha" or body.get("result", {}).get("status") == "need_captcha":
                log_warn(f"{self._lp}: требуется капча")
                self._handle_captcha(s, auth_payload, auth_headers, body)
                s.close()
                return

            if not body.get("success"):
                err_status = body.get("result", {}).get("status", "unknown")
                self._consecutive_login_failures += 1
                log_err(f"{self._lp}: authenticate failed: {err_status} (попытка {self._consecutive_login_failures}/{MAX_LOGIN_FAILURES})")
                s.close()
                if self._consecutive_login_failures >= MAX_LOGIN_FAILURES:
                    raise PermissionError(
                        f"Reg.ru: {MAX_LOGIN_FAILURES} подряд неудач — "
                        f"статус: {err_status} (login: {self._login})"
                    )
                return

            # Успешная авторизация
            self._consecutive_login_failures = 0
            user_id = body.get("result", {}).get("user_id", "?")
            log_ok(f"{self._lp}: authenticate OK (user_id={user_id})")

            for cookie in resp.cookies:
                self._cookies[cookie.name] = cookie.value
                if cookie.name == "SESSION_ID":
                    self._session_id = cookie.value

            # ── Шаг 2: Refresh для получения JWT ──
            cookie_parts_2 = [f"{k}={v}" for k, v in self._cookies.items()]
            refresh_cookie_header = "; ".join(cookie_parts_2)

            refresh_headers = {
                "User-Agent": self._fingerprint.get("ua", ""),
                "Accept": "application/json, text/plain, */*",
                "Content-Length": "0",
                "Origin": ORIGIN,
                "Referer": REFERER,
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Cookie": refresh_cookie_header,
            }
            csrf_new = self._cookies.get("csrftoken", "")
            if csrf_new:
                refresh_headers["x-csrf-token"] = csrf_new

            resp2 = s.post(REFRESH_URL, headers=refresh_headers, timeout=15)
            s.close()

            if resp2.status_code != 200:
                log_warn(f"{self._lp}: post-login refresh HTTP {resp2.status_code}: {resp2.text[:200]}")
                return

            new_jwt, new_refresh = self._extract_jwt_from_response(resp2)

            if new_jwt and "." in new_jwt:
                self._jwt = new_jwt
                self._jwt_expires = _parse_jwt_expiry(new_jwt)
                ttl = int(self._jwt_expires - time.time())

                if self.session:
                    self.session.cookies.set("JWT", new_jwt, domain=".reg.ru")

                if new_refresh and new_refresh != '""' and len(new_refresh) > 10:
                    self._cookies["JWT_REFRESH"] = new_refresh

                log_ok(f"{self._lp}: полный логин OK, JWT TTL: {ttl}с")
                self._sync_cookies_to_session()
            else:
                # Детальный лог для диагностики
                log_warn(f"{self._lp}: post-login refresh не вернул JWT")
                log_debug(f"{self._lp}: resp2.cookies: {dict(resp2.cookies)}")
                try:
                    sc_headers = resp2.headers.get("Set-Cookie", "")
                    log_debug(f"{self._lp}: Set-Cookie header: {sc_headers[:300]}")
                except Exception:
                    pass
                log_debug(f"{self._lp}: resp2 body: {resp2.text[:300]}")

        except PermissionError:
            raise
        except Exception as e:
            log_err(f"{self._lp}: полный логин ошибка: {e}")

    def _handle_captcha(self, s, auth_payload, auth_headers, auth_result):
        """Обработка капчи при логине. После успеха — refresh для JWT."""
        if not self._captcha_api_key:
            log_err(f"{self._lp}: нет captcha_api_key")
            return
        sitekey, ctype = detect_captcha(s, self._fingerprint.get("ua", ""))
        if not sitekey:
            log_err(f"{self._lp}: sitekey не найден")
            return
        token = solve_captcha(self._captcha_api_key, sitekey, ctype)
        if not token:
            log_err(f"{self._lp}: капча не решена")
            return
        key = "h-captcha-response" if ctype == "hcaptcha" else "g-recaptcha-response"
        auth_payload[key] = token
        try:
            resp2 = s.post(AUTHENTICATE_URL, json=auth_payload, headers=auth_headers, timeout=15)
            result2 = resp2.json()
        except Exception as exc:
            log_err(f"{self._lp}: повторный authenticate: {exc}")
            return
        if not result2.get("success"):
            log_err(f"{self._lp}: логин после капчи: {result2}")
            return
        self._consecutive_login_failures = 0
        # Собираем cookies после успешного authenticate
        for cookie in resp2.cookies:
            self._cookies[cookie.name] = cookie.value
            if cookie.name == "SESSION_ID":
                self._session_id = cookie.value

        # ── Refresh для получения JWT (как в основном flow _do_full_login) ──
        cookie_parts_r = [f"{k}={v}" for k, v in self._cookies.items()]
        refresh_cookie_header = "; ".join(cookie_parts_r)
        csrf_new = self._cookies.get("csrftoken", "")
        refresh_headers = {
            "User-Agent": self._fingerprint.get("ua", ""),
            "Accept": "application/json, text/plain, */*",
            "Content-Length": "0",
            "Origin": ORIGIN,
            "Referer": REFERER,
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Cookie": refresh_cookie_header,
        }
        if csrf_new:
            refresh_headers["x-csrf-token"] = csrf_new

        try:
            resp3 = s.post(REFRESH_URL, headers=refresh_headers, timeout=15)
            if resp3.status_code == 200:
                new_jwt, new_refresh = self._extract_jwt_from_response(resp3)
                if new_jwt and "." in new_jwt:
                    self._jwt = new_jwt
                    self._jwt_expires = _parse_jwt_expiry(new_jwt)
                    ttl = int(self._jwt_expires - time.time())
                    if self.session:
                        self.session.cookies.set("JWT", new_jwt, domain=".reg.ru")
                    if new_refresh and new_refresh != '""' and len(new_refresh) > 10:
                        self._cookies["JWT_REFRESH"] = new_refresh
                    log_ok(f"{self._lp}: логин через капчу OK, JWT TTL: {ttl}с")
                    self._sync_cookies_to_session()
                else:
                    log_debug(f"{self._lp}: post-captcha refresh не вернул JWT")
            else:
                log_debug(f"{self._lp}: post-captcha refresh HTTP {resp3.status_code}")
        except Exception as exc:
            log_err(f"{self._lp}: post-captcha refresh ошибка: {exc}")

    def _ensure_jwt_valid(self):
        """Проверяет JWT и обновляет если скоро истечёт."""
        with self._jwt_lock:
            if time.time() > self._jwt_expires - 60:
                self._do_refresh_jwt()

    # ── init_session (из v11) ──

    def init_session(self) -> None:
        cfg = self.cfg

        if not self._has_credentials:
            token = cfg.get("token", "")
            if not token:
                raise RuntimeError(
                    "Нет логина/пароля и нет cookie для Reg.ru"
                )

        if not self._service_id:
            raise RuntimeError("Нет service_id для Reg.ru")

        # Парсим cookies из token строки
        cookies_str = cfg.get("token", "")
        parsed_cookies = {}
        if cookies_str and cookies_str != "login_mode":
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
        self._jwt = parsed_cookies.get("JWT", "")
        self._cookies = parsed_cookies

        if self._jwt:
            self._jwt_expires = _parse_jwt_expiry(self._jwt)
            ttl = max(0, int(self._jwt_expires - time.time()))
            log_info(f"{self._lp}: JWT TTL: {ttl}с")

        # Fingerprint и сессия
        self._fingerprint = self._pick_fingerprint()
        browser_headers = self._build_browser_headers()

        self.session = make_session(token="", auth_header="X-Auth-Token", proxy=self.proxy)
        self.session.headers.update(browser_headers)
        self.session.headers["service-id"] = self._service_id
        self.session.headers.pop("Authorization", None)
        self.session.headers.pop("X-Auth-Token", None)

        for k, v in self._cookies.items():
            self.session.cookies.set(k, v, domain=".reg.ru")
            self.session.cookies.set(k, v, domain="login.reg.ru")

        # Авторизация
        if self._has_credentials and (not self._jwt or time.time() > self._jwt_expires):
            log_info(f"{self._lp}: полный логин...")
            with self._jwt_lock:
                self._do_full_login()
        elif self._session_id and (not self._jwt or time.time() > self._jwt_expires):
            log_info(f"{self._lp}: JWT просрочен, refresh...")
            self._refresh_jwt()

        # Проверяем что JWT получен
        if not self._jwt or time.time() > self._jwt_expires:
            raise RuntimeError(f"{self._lp}: JWT не получен после авторизации")

        # Проверка API
        log_debug(f"{self._lp}: проверка GraphQL API...")
        self._human_delay()
        try:
            test_resp = self.session.post(
                GRAPHQL_URL,
                json={
                    "operationName": "server",
                    "variables": {"serverId": 0},
                    "query": SERVER_QUERY,
                },
                timeout=self.timeout,
            )
            if test_resp.status_code == 401:
                raise PermissionError("Токен/cookie невалидны (401)")
            if test_resp.status_code == 403:
                raise PermissionError("Доступ запрещён (403)")

            try:
                body = test_resp.json()
                srv = body.get("data", {}).get("server", {})
                if isinstance(srv, dict) and srv.get("__typename") == "Unauthorized":
                    raise PermissionError("API Unauthorized — обновите cookie")
            except (json.JSONDecodeError, AttributeError):
                pass

            log_ok(f"{self._lp}: GraphQL API доступен (HTTP {test_resp.status_code})")
        except requests.RequestException as e:
            log_warn(f"{self._lp}: API недоступен ({e}) — продолжаю")

    # ── GraphQL (из v11) ──

    def _graphql(self, operation_name: str, query: str, variables: dict,
                 is_mutation: bool = False) -> dict:
        self._ensure_jwt_valid()
        self._human_delay(is_mutation=is_mutation)
        self._maybe_rotate_fingerprint()

        payload = {
            "operationName": operation_name,
            "variables": variables,
            "query": query,
        }

        for attempt in range(2):
            # Cookie header с актуальным JWT
            cookie_parts = []
            for k, v in self._cookies.items():
                if k.upper() not in ("JWT",):
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
                raise PermissionError("Токен/cookie невалидны (401)")
            if resp.status_code == 403:
                raise PermissionError(f"Доступ запрещён (403): {resp.text[:300]}")
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"GraphQL HTTP {resp.status_code}: {resp.text[:400]}")

            body = resp.json()
            if "errors" in body and body["errors"]:
                err_msgs = "; ".join(e.get("message", str(e)) for e in body["errors"])
                raise RuntimeError(f"GraphQL errors: {err_msgs}")

            data = body.get("data", {})

            # Проверяем Unauthorized в ответе
            data_str = json.dumps(data)
            if '"Unauthorized"' in data_str:
                if attempt == 0 and self._session_id:
                    log_debug(f"{self._lp}: Unauthorized в ответе, обновляю JWT...")
                    self._refresh_jwt()
                    continue
                raise PermissionError("API Unauthorized — SESSION_ID невалиден")

            return data

        raise RuntimeError("Не удалось после обновления JWT")

    # ── Server operations (из v11) ──

    def _create_single_server(self, region: str) -> tuple[int, str]:
        server_name = _random_server_name()
        variables = {
            "name": server_name,
            "region": region,
            "image": self._image,
            "plan": self._plan,
            "sshKey": "",
            "enableBackups": False,
            "enableFloatingIp": True,
            "promocode": "",
            "volumeIds": [],
            "protectedIPPlan": "",
            "commercialSoftwarePlan": None,
        }

        data = self._graphql("createServer", CREATE_SERVER_MUTATION, variables,
                             is_mutation=True)

        create_result = data.get("server", {}).get("create", {})
        typename = create_result.get("__typename", "")

        if typename == "ServerLimitReached":
            raise RuntimeError("ServerLimitReached — лимит серверов")

        if create_result.get("message") and not create_result.get("id"):
            err_msg = create_result.get("message", str(create_result))
            if "лимит" in err_msg.lower() or "limit" in err_msg.lower():
                raise DailyLimitError(f"Reg.ru: {err_msg}")
            if "баланс" in err_msg.lower() or "balance" in err_msg.lower() or "средств" in err_msg.lower():
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
                log_info(f"{self._lp}: сервер #{server_id} — IP из ipv4 (floatingIPs пуст): {ipv4}")
                return ipv4

        return None

    def create_ip(self, region: str) -> ProviderResult:
        from ip_hunter.worker import is_shutdown

        # Retry loop для ServerLimitReached
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
                        wait = 10 + create_attempt * 5
                        log_debug(f"{self._lp}: лимит серверов, жду {wait}с ({create_attempt+1}/5)")
                        time.sleep(wait)
                    continue
                raise
        else:
            raise RuntimeError("ServerLimitReached — 5 попыток")

        log_info(f"{self._lp}: сервер #{server_id} '{server_name}' создаётся...")

        # Поллинг IP
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

        # Таймаут
        try:
            self._remove_server(server_id)
        except Exception:
            pass
        raise RuntimeError(f"Таймаут {IP_POLL_TIMEOUT}с: сервер #{server_id} не получил IP")

    def _remove_server(self, server_id: int):
        """Удаляет сервер и ждёт подтверждения (из v11)."""
        variables = {
            "serverId": server_id,
            "releaseFloatingIPs": [],
            "releaseVolumes": [],
        }
        data = self._graphql("removeServer", REMOVE_SERVER_MUTATION, variables,
                             is_mutation=True)
        remove_result = data.get("server", {}).get("remove", {})
        if remove_result.get("message") and not remove_result.get("id"):
            raise RuntimeError(f"removeServer: {remove_result['message']}")

        # Поллинг до реального удаления
        for poll_i in range(12):
            time.sleep(2.0)
            try:
                poll_data = self._graphql("server", SERVER_QUERY, {"serverId": server_id})
                srv = poll_data.get("server", {})
                status = srv.get("status", "")
                typename = srv.get("__typename", "")
                if status in ("deleted", "") or typename in ("NotFound", "ServerNotFound"):
                    break
                if status == "deleting":
                    continue
            except Exception:
                break
        log_debug(f"{self._lp}: сервер #{server_id} удалён")

    def delete_ip(self, resource_id: str):
        try:
            server_id = int(resource_id)
        except (ValueError, TypeError):
            log_warn(f"{self._lp}: невалидный resource_id: {resource_id}")
            return
        self._remove_server(server_id)

    def cleanup_zombie_servers(self):
        """Удаляет все серверы (из v11)."""
        try:
            all_items = []
            page = 1
            while True:
                data = self._graphql("serverList", SERVERS_LIST_QUERY, {"page": page})
                servers_data = data.get("serverList", {})
                items = servers_data.get("items", []) or servers_data.get("nodes", [])
                if items:
                    all_items.extend(items)
                meta = servers_data.get("meta", {})
                last_page = meta.get("lastPage", 1)
                if page >= last_page:
                    break
                page += 1

            alive = [s for s in all_items if s.get("status") not in ("deleting", "deleted")]
            if not alive:
                return
            log_info(f"{self._lp}: найдено {len(alive)} серверов, удаляю...")
            for srv in alive:
                sid = srv.get("id")
                if not sid:
                    continue
                try:
                    self._remove_server(int(sid))
                except Exception as e:
                    log_debug(f"{self._lp}: не удалось удалить #{sid}: {e}")
            log_ok(f"{self._lp}: очистка завершена ({len(alive)} серверов)")
        except Exception as e:
            log_debug(f"{self._lp}: ошибка получения списка: {e}")

    def list_ips(self) -> list[ProviderResult]:
        """Reg.ru не имеет отдельного list floating IPs — возвращаем пустой список."""
        return []
