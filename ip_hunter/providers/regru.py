# Reg.ru Cloud VPS provider — GraphQL API with browser emulation
import base64
import json
import random
import re
import threading
import time
from typing import Optional

import requests

from ip_hunter.captcha import detect_captcha, solve_captcha
from ip_hunter.logger import log_debug, log_err, log_info, log_warn
from ip_hunter.providers.base import BaseProvider, DailyLimitError, ProviderResult
from ip_hunter.proxy import apply_proxy_to_session

GRAPHQL_URL = "https://cloudvps-graphql-server.svc.reg.ru/api"
ORIGIN = "https://cloud.reg.ru"
REFERER = "https://cloud.reg.ru/"
AUTHENTICATE_URL = "https://login.reg.ru/authenticate"
REFRESH_URL = "https://login.reg.ru/refresh"
IP_POLL_TIMEOUT = 120
HUMAN_DELAY_QUERY = (0.2, 0.8)
HUMAN_DELAY_MUTATION = (0.5, 1.5)
MAX_LOGIN_FAILURES = 3

# -- GraphQL --
GQL_CREATE_SERVER = (
    "mutation createServer($name:String!,$region:String!,$image:String!,$plan:String!,"
    "$sshKey:String!,$enableBackups:Boolean!,$enableFloatingIp:Boolean!,"
    "$promocode:String!,$volumeIds:[Int!]!,$protectedIPPlan:String!,"
    "$commercialSoftwarePlan:String){server{create(params:{name:$name,region:$region,"
    "image:$image,plan:$plan,sshKey:$sshKey,enableBackups:$enableBackups,"
    "enableFloatingIp:$enableFloatingIp,promocode:$promocode,volumeIds:$volumeIds,"
    "protectedIPPlan:$protectedIPPlan,commercialSoftwarePlan:$commercialSoftwarePlan})"
    "{__typename ...on Server{id name status ipv4}}}}"
)
GQL_GET_SERVER = (
    "query server($serverId:Int!){server(serverId:$serverId)"
    "{__typename ...on Server{id name ipv4 status floatingIPs{id address}}}}"
)
GQL_REMOVE_SERVER = (
    "mutation removeServer($serverId:Int!,$releaseFloatingIPs:[Int!]!,$releaseVolumes:[Int!]!)"
    "{server{remove(params:{serverId:$serverId,releaseFloatingIPs:$releaseFloatingIPs,"
    "releaseVolumes:$releaseVolumes}){__typename ...on Server{id status}}}}"
)
GQL_SERVER_LIST = (
    "query serverList($page:Int!,$perPage:Int!){serverList(page:$page,perPage:$perPage)"
    "{%LIST_FIELD%{id name status ipv4} %META_FIELD%{totalCount}}}"
)
GQL_INTROSPECT = '{__type(name:"ServerList"){fields{name type{name kind ofType{name kind}}}}}'
def _fp(ua, ch="", mob="", plat=""):
    return {"ua": ua, "sec_ch_ua": ch, "sec_ch_ua_mobile": mob, "sec_ch_ua_platform": plat}

_CH146 = '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"'
_CH145 = '"Chromium";v="145", "Not-A.Brand";v="24", "Google Chrome";v="145"'
_EDGE = '"Chromium";v="146", "Microsoft Edge";v="146", "Not-A.Brand";v="24"'
FINGERPRINTS = [
    _fp("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", _CH146, "?0", '"Windows"'),
    _fp("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", _CH146, "?0", '"macOS"'),
    _fp("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", _CH146, "?0", '"Linux"'),
    _fp("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", _CH145, "?0", '"Windows"'),
    _fp("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"),
]
_ADJECTIVES = ["Swift", "Brave", "Calm", "Dark", "Epic", "Fast", "Grand", "High", "Iron", "Keen"]
_NOUNS = ["Fox", "Bear", "Wolf", "Hawk", "Lion", "Lynx", "Pike", "Rook", "Viper", "Crane"]
_schema_lock = threading.Lock()

def _random_server_name() -> str:
    """Generate random server name like 'Swift Fox 742'."""
    return f"{random.choice(_ADJECTIVES)} {random.choice(_NOUNS)} {random.randint(100, 999)}"
def _decode_jwt_exp(jwt_str: str) -> float:
    """Extract exp from JWT payload without signature verification."""
    try:
        payload = jwt_str.split(".")[1]
        payload += "=" * (4 - len(payload) % 4) if len(payload) % 4 else ""
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
    except Exception: return 0.0

class RegruProvider(BaseProvider):
    """Reg.ru Cloud VPS provider via GraphQL with browser emulation."""
    name: str = "regru"
    _schema_list_field: Optional[str] = None
    _schema_meta_field: Optional[str] = None
    def __init__(self, cfg: dict, timeout: tuple[int, int] = (10, 30),
                 proxy: Optional[dict] = None) -> None:
        super().__init__(cfg, timeout, proxy)
        self._login, self._password = cfg.get("login", ""), cfg.get("password", "")
        self._captcha_api_key = cfg.get("captcha_api_key", "")
        self._image = cfg.get("image", "ubuntu-24-04-x64")
        self._plan = cfg.get("plan", "cloud-2-1-20-ISPmanager")
        self._instance_label = cfg.get("label", "regru")
        self._jwt, self._jwt_expires, self._jwt_refresh_cooldown = "", 0.0, 0.0
        self._jwt_lock = threading.Lock()
        self._fp, self._fp_counter = random.choice(FINGERPRINTS), 0
        self._fp_rotate_at = random.randint(30, 60)
        self._login_failures, self._cooldown_until = 0, 0.0
    def init_session(self) -> None:
        """Initialize session and perform initial login."""
        self.session = requests.Session()
        if self.proxy: apply_proxy_to_session(self.session, self.proxy)
        self._login_with_csrf_retry()
        log_info(f"[Regru] Сессия готова ({self._instance_label})")
    @property
    def current_account_label(self) -> str:
        """Return human-readable account label."""
        return self._instance_label
    def get_regions(self) -> list[str]:
        """Return configured region list."""
        return self.cfg.get("regions", ["msk1"])
    def _login_with_csrf_retry(self) -> None:
        """Attempt _do_full_login with up to 3 retries on CSRF_CHECK_FAILED."""
        for attempt in range(3):
            try: self._do_full_login(); return
            except RuntimeError as exc:
                if "CSRF_CHECK_FAILED" in str(exc) and attempt < 2:
                    log_warn(f"[Regru] CSRF retry {attempt+1}/3"); time.sleep(2)
                else: raise
    def _do_full_login(self) -> None:
        """Full login: GET login page → POST authenticate → POST refresh."""
        s = requests.Session()
        if self.proxy: apply_proxy_to_session(s, self.proxy)
        ua = self._fp["ua"]
        base_hdrs = {"User-Agent": ua, "Accept": "application/json",
                     "Origin": ORIGIN, "Referer": REFERER}
        login_resp = None
        for login_url in ("https://www.reg.ru/user/authorize", "https://login.reg.ru/"):
            try:
                r = s.get(login_url, headers={"User-Agent": ua}, timeout=(10, 20))
                log_debug(f"[Regru] {login_url} → {r.status_code}")
                # Берём любой ответ с телом — CSRF может быть даже в 403
                if r.status_code == 200:
                    login_resp = r
                    break
                # 403/другое — всё равно попробуем достать CSRF
                if login_resp is None and len(r.text) > 500:
                    login_resp = r
            except Exception as exc:
                log_debug(f"[Regru] GET {login_url}: {exc}")
        csrf = self._extract_csrf(s, login_resp)
        log_debug(f"[Regru] CSRF: '{csrf[:24]}' (len={len(csrf)})")
        if not csrf: log_warn("[Regru] CSRF пустой — логин может не сработать")
        # login.reg.ru проверяет CSRF через cookie + header
        if csrf:
            s.cookies.set("csrftoken", csrf, domain=".reg.ru")
        payload: dict = {"login": self._login, "password": self._password}
        auth_hdrs = {**base_hdrs, "x-csrf-token": csrf}
        try: resp = s.post(AUTHENTICATE_URL, json=payload, headers=auth_hdrs, timeout=(10, 30))
        except Exception as exc: log_err(f"[Regru] POST authenticate: {exc}"); raise
        if resp.status_code == 401:
            self._login_failures += 1
            if self._login_failures >= MAX_LOGIN_FAILURES:
                raise PermissionError(f"Regru: {self._login_failures} ошибок логина")
            raise RuntimeError("Regru: 401")
        if resp.status_code == 400:
            try:
                err_msg = str(resp.json()) if resp.text else ""
            except (ValueError, TypeError):
                err_msg = resp.text[:200] if resp.text else ""
            if "CSRF_CHECK_FAILED" in err_msg:
                s.cookies.pop("csrftoken", None)
                raise RuntimeError("Regru: CSRF_CHECK_FAILED, retry needed")
            if "ACCESS_LIMIT" in err_msg:
                self._cooldown_until = time.time() + 3600
                raise RuntimeError("Regru: ACCESS_LIMIT")
        try: auth_result = resp.json()
        except ValueError as exc: raise RuntimeError(f"Regru authenticate JSON: {exc}") from exc
        status, success = auth_result.get("status", ""), auth_result.get("success", False)
        if status == "need_captcha":
            self._handle_captcha(s, ua, payload, auth_hdrs, auth_result); return
        if not success and status != "authenticated":
            self._login_failures += 1
            if self._login_failures >= MAX_LOGIN_FAILURES:
                raise PermissionError(f"Regru: {self._login_failures} ошибок логина")
            raise RuntimeError(f"Regru authenticate failed: {auth_result}")
        self._login_failures = 0
        self._do_refresh_from_session(s, ua)
    def _handle_captcha(self, s: requests.Session, ua: str,
                        payload: dict, auth_hdrs: dict, auth_result: dict) -> None:
        """Handle captcha challenge during login."""
        log_warn("[Regru] Требуется капча")
        def _cooldown():
            self._cooldown_until = time.time() + 3600
        if not self._captcha_api_key:
            log_err("[Regru] Нет captcha_api_key"); _cooldown(); return
        sitekey, ctype = detect_captcha(s, ua)
        if not sitekey:
            log_err("[Regru] Sitekey не найден"); _cooldown(); return
        token = solve_captcha(self._captcha_api_key, sitekey, ctype)
        if not token:
            log_err("[Regru] Капча не решена"); _cooldown(); return
        key = "h-captcha-response" if ctype == "hcaptcha" else "g-recaptcha-response"
        payload[key] = token
        try:
            resp2 = s.post(AUTHENTICATE_URL, json=payload, headers=auth_hdrs, timeout=(10, 30))
            result2 = resp2.json()
        except Exception as exc:
            log_err(f"[Regru] Повторный authenticate: {exc}"); _cooldown(); return
        if not result2.get("success") and result2.get("status") != "authenticated":
            log_err(f"[Regru] Логин после капчи: {result2}"); _cooldown(); return
        self._login_failures = 0
        self._do_refresh_from_session(s, ua)
    def _do_refresh_from_session(self, s: requests.Session, ua: str) -> None:
        """POST /refresh on the same session to obtain JWT."""
        try: resp = s.post(REFRESH_URL, headers={"User-Agent": ua, "Origin": ORIGIN,
                                                  "Referer": REFERER}, timeout=(10, 30))
        except Exception as exc: log_err(f"[Regru] POST refresh: {exc}"); raise
        jwt = self._extract_jwt(s, resp)
        if not jwt: raise RuntimeError("Regru: JWT не получен из refresh")
        exp = _decode_jwt_exp(jwt)
        self._jwt, self._jwt_expires = jwt, (exp if exp > 0 else time.time() + 3600)
        if self.session: self.session.cookies.set("jwt", jwt, domain=".reg.ru")
    def _extract_csrf(self, s: requests.Session, resp) -> str:
        """Extract CSRF token from cookies, Set-Cookie, or HTML meta tag."""
        for name in ("csrftoken", "csrf_token", "CSRF-TOKEN", "_csrf"):
            if s.cookies.get(name, ""): return s.cookies[name]
        if resp is None: return ""
        for name in ("csrftoken", "csrf_token"):
            m = re.search(name + r'=([^;]+)', resp.headers.get("Set-Cookie", ""))
            if m: return m.group(1)
        body = getattr(resp, "text", "") or ""
        for pat in (
            r'name=["\']_csrf["\'][^>]*content=["\']([^"\']+)',
            r'content=["\']([^"\']+)["\'][^>]*name=["\']_csrf["\']',
            r'name=["\']csrf[_-]?token["\'][^>]*content=["\']([^"\']+)',
            r'content=["\']([^"\']+)["\'][^>]*name=["\']csrf[_-]?token',
        ):
            m = re.search(pat, body)
            if m: return m.group(1)
        return ""
    def _extract_jwt(self, s: requests.Session, resp: requests.Response) -> str:
        """Extract JWT from session cookies, response cookies, or Set-Cookie header."""
        for src in (s.cookies, resp.cookies):
            if src.get("jwt", ""): return src["jwt"]
        m = re.search(r'jwt=([^;]+)', resp.headers.get("Set-Cookie", ""))
        return m.group(1) if m else ""
    def _ensure_jwt_valid(self) -> None:
        """Ensure JWT is valid, refreshing if needed."""
        with self._jwt_lock:
            now = time.time()
            if now < self._jwt_expires - 60: return
            if now < self._jwt_refresh_cooldown:
                raise RuntimeError(f"JWT expired, cooldown ещё {int(self._jwt_refresh_cooldown-now)}с")
            try: self._login_with_csrf_retry()
            except Exception as exc: log_debug(f"[Regru] Ре-логин: {exc}")
            if time.time() > self._jwt_expires - 60:
                self._jwt_refresh_cooldown = time.time() + 300
                raise RuntimeError("JWT не получен после ре-логина")
    def _graphql(self, op: str, query: str, variables: dict,
                 is_mutation: bool = False, _retry: bool = True) -> dict:
        """Execute a GraphQL request with JWT auth and browser emulation."""
        self._ensure_jwt_valid()
        time.sleep(random.uniform(*(HUMAN_DELAY_MUTATION if is_mutation else HUMAN_DELAY_QUERY)))
        self._fp_counter += 1
        if self._fp_counter >= self._fp_rotate_at:
            self._fp, self._fp_counter = random.choice(FINGERPRINTS), 0
            self._fp_rotate_at = random.randint(30, 60)
        fp = self._fp
        hdrs: dict[str, str] = {
            "User-Agent": fp["ua"], "Origin": ORIGIN, "Referer": REFERER,
            "Content-Type": "application/json", "Accept": "application/json",
            "Cookie": f"jwt={self._jwt}"}
        if fp["sec_ch_ua"]:
            hdrs.update({"sec-ch-ua": fp["sec_ch_ua"], "sec-ch-ua-mobile": fp["sec_ch_ua_mobile"],
                         "sec-ch-ua-platform": fp["sec_ch_ua_platform"]})
        body = {"operationName": op, "query": query, "variables": variables}
        if self.session is None: raise RuntimeError("Сессия не инициализирована")
        resp = self.session.post(GRAPHQL_URL, json=body, headers=hdrs, timeout=self.timeout)
        if resp.status_code == 401 and _retry:
            with self._jwt_lock:
                try: self._do_full_login()
                except Exception as exc: log_debug(f"[Regru] Ре-логин 401: {exc}")
            return self._graphql(op, query, variables, is_mutation, False)
        if resp.status_code != 200:
            raise RuntimeError(f"Regru GraphQL HTTP {resp.status_code}: {resp.text[:200]}")
        try: data = resp.json()
        except ValueError as exc:
            raise RuntimeError(f"Regru GraphQL JSON: {exc}") from exc
        for err in data.get("errors", []):
            if "nauthorized" in err.get("message", ""):
                if _retry:
                    with self._jwt_lock:
                        try: self._do_full_login()
                        except Exception: pass
                    return self._graphql(op, query, variables, is_mutation, False)
                raise RuntimeError(f"Regru Unauthorized: {err['message']}")
        return data
    def create_ip(self, region: str) -> ProviderResult:
        """Create a server with floating IP and return the IP."""
        if time.time() < self._cooldown_until:
            raise RuntimeError(f"Regru cooldown ещё {int(self._cooldown_until - time.time())}с")
        server_id = None
        for attempt in range(5):
            try:
                server_id, _ = self._create_single_server(region); break
            except RuntimeError as exc:
                msg = str(exc).lower()
                if "лимит" in msg or "limit" in msg: raise DailyLimitError(str(exc)) from exc
                if "баланс" in msg or "balance" in msg or "средств" in msg:
                    raise PermissionError(str(exc)) from exc
                if "serverlimitreached" in msg or "server_limit" in msg:
                    log_warn(f"[Regru] ServerLimitReached, cleanup ({attempt+1}/5)")
                    self.cleanup_zombie_servers(); continue
                raise
        else:
            raise RuntimeError("Regru: не удалось создать сервер после 5 попыток")
        try: result = self._poll_server_ip(server_id, region)
        except Exception:
            self._remove_server(server_id); raise
        result.resource_id = str(server_id)
        return result
    def _create_single_server(self, region: str) -> tuple[int, str]:
        """Create a single server via GraphQL mutation."""
        name = _random_server_name()
        v = {"name": name, "region": region, "image": self._image, "plan": self._plan,
             "sshKey": "", "enableBackups": False, "enableFloatingIp": True,
             "promocode": "", "volumeIds": [], "protectedIPPlan": "",
             "commercialSoftwarePlan": None}
        data = self._graphql("createServer", GQL_CREATE_SERVER, v, is_mutation=True)
        if data.get("errors"): raise RuntimeError(f"createServer: {data['errors']}")
        srv = data.get("data", {}).get("server", {}).get("create", {})
        if not srv.get("id"): raise RuntimeError(f"createServer нет id: {data}")
        return (int(srv["id"]), srv.get("name", name))
    def _poll_server_ip(self, server_id: int, region: str) -> ProviderResult:
        """Poll server until floating IP is assigned."""
        deadline = time.time() + IP_POLL_TIMEOUT
        while time.time() < deadline:
            time.sleep(random.uniform(2, 5))
            data = self._graphql("server", GQL_GET_SERVER, {"serverId": server_id})
            srv = data.get("data", {}).get("server", {})
            fips = srv.get("floatingIPs") or []
            if fips and fips[0].get("address"):
                return ProviderResult(ip=fips[0]["address"], resource_id=str(server_id),
                                      region=region, raw=srv)
            if srv.get("status") == "active" and not fips and srv.get("ipv4"):
                log_warn(f"[Regru] floatingIPs пуст, fallback ipv4: {srv['ipv4']}")
                return ProviderResult(ip=srv["ipv4"], resource_id=str(server_id),
                                      region=region, raw=srv)
        raise RuntimeError(f"Regru: таймаут {IP_POLL_TIMEOUT}с для сервера {server_id}")
    def delete_ip(self, resource_id: str) -> None:
        """Delete server by ID, releasing its floating IPs."""
        sid = int(resource_id)
        fip_ids: list[int] = []
        try:
            srv = self._graphql("server", GQL_GET_SERVER, {"serverId": sid}).get(
                "data", {}).get("server", {})
            fip_ids = [int(f["id"]) for f in (srv.get("floatingIPs") or []) if f.get("id")]
        except Exception as exc:
            log_debug(f"[Regru] floatingIPs fetch {sid}: {exc}")
        self._remove_server(sid, release_fips=fip_ids)
    def _remove_server(self, server_id: int, wait: bool = False,
                       release_fips: list | None = None) -> None:
        """Remove a server via GraphQL mutation."""
        v = {"serverId": server_id, "releaseFloatingIPs": release_fips or [],
             "releaseVolumes": []}
        try: self._graphql("removeServer", GQL_REMOVE_SERVER, v, is_mutation=True)
        except Exception as exc: log_debug(f"[Regru] removeServer {server_id}: {exc}"); return
        if not wait: return
        for _ in range(4):
            time.sleep(3)
            try:
                d = self._graphql("server", GQL_GET_SERVER, {"serverId": server_id})
                if d.get("data", {}).get("server", {}).get("status", "") in ("deleted", "deleting"):
                    return
            except Exception as exc: log_debug(f"[Regru] poll delete {server_id}: {exc}")
    def _discover_schema(self) -> tuple[str, str]:
        """Discover serverList schema fields via introspection, with fallback."""
        cls = type(self)
        with _schema_lock:
            if cls._schema_list_field and cls._schema_meta_field:
                return (cls._schema_list_field, cls._schema_meta_field)
        try:
            fields = self._graphql("introspect", GQL_INTROSPECT, {}).get(
                "data", {}).get("__type", {}).get("fields", [])
            lf = mf = ""
            for f in fields:
                nm, k = f.get("name", ""), f.get("type", {}).get("kind", "")
                ik = (f.get("type", {}).get("ofType") or {}).get("kind", "")
                if k == "LIST" or ik == "LIST": lf = nm
                elif "meta" in nm.lower() or "pagination" in nm.lower(): mf = nm
            if lf and mf:
                with _schema_lock: cls._schema_list_field, cls._schema_meta_field = lf, mf
                return (lf, mf)
        except Exception as exc: log_debug(f"[Regru] Introspection: {exc}")
        _LIST_CANDIDATES = ("serverList", "servers", "data", "items", "nodes", "reglets")
        _META_CANDIDATES = ("meta", "paginatorInfo", "pageInfo", "pagination")
        for lf in _LIST_CANDIDATES:
            for mf in _META_CANDIDATES:
                q = GQL_SERVER_LIST.replace("%LIST_FIELD%", lf).replace("%META_FIELD%", mf)
                try:
                    if self._graphql("serverList", q, {"page": 1, "perPage": 1}).get(
                            "data", {}).get("serverList"):
                        with _schema_lock: cls._schema_list_field, cls._schema_meta_field = lf, mf
                        return (lf, mf)
                except Exception: continue
        raise RuntimeError("Regru: schema serverList не определена")
    def cleanup_zombie_servers(self) -> None:
        """Remove all non-deleted/non-deleting servers."""
        log_info("[Regru] Очистка зомби-серверов...")
        lf, mf = self._discover_schema()
        q = GQL_SERVER_LIST.replace("%LIST_FIELD%", lf).replace("%META_FIELD%", mf)
        page, removed = 1, 0
        while True:
            sl = self._graphql("serverList", q, {"page": page, "perPage": 50}).get(
                "data", {}).get("serverList", {})
            srvs = sl.get(lf, []) or []
            if not srvs: break
            for srv in srvs:
                if srv.get("status") not in ("deleting", "deleted") and srv.get("id"):
                    try: self.delete_ip(str(srv["id"]))
                    except Exception as exc: log_debug(f"[Regru] Zombie {srv['id']}: {exc}")
                    removed += 1; time.sleep(8)
            if page * 50 >= (sl.get(mf) or {}).get("totalCount", 0): break
            page += 1
        log_info(f"[Regru] Очистка: удалено {removed}")
