"""Timeweb Cloud provider — Floating IP management."""

from typing import Optional

from ip_hunter.logger import log_debug, log_err, log_info, log_warn
from ip_hunter.providers.base import BaseProvider, DailyLimitError, ProviderResult
from ip_hunter.session import make_session


class TimewebProvider(BaseProvider):
    """Timeweb Cloud Floating IP provider."""

    name: str = "timeweb"
    BASE: str = "https://api.timeweb.cloud/api/v1"

    def __init__(
        self,
        cfg: dict,
        timeout: tuple[int, int] = (10, 30),
        proxy: Optional[dict] = None,
    ) -> None:
        super().__init__(cfg, timeout, proxy)
        self._token: str = cfg.get("token", "")
        self._instance_label: str = cfg.get("label", "timeweb")

    def init_session(self) -> None:
        """Initialize HTTP session with Bearer auth."""
        if not self._token:
            raise ValueError("Timeweb: отсутствует token в конфиге")
        self.session = make_session(self._token, "Authorization", self.proxy)
        log_info(f"[Timeweb] Сессия готова ({self._instance_label})")

    @property
    def current_account_label(self) -> str:
        """Return human-readable account label."""
        return self._instance_label

    def get_regions(self) -> list[str]:
        """Return configured region list."""
        return self.cfg.get("regions", ["spb-2", "spb-3"])

    def list_ips(self) -> list[ProviderResult]:
        """List all active floating IPs."""
        url = f"{self.BASE}/floating-ips"
        if self.session is None: return []
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                log_debug(f"[Timeweb] list_ips HTTP {resp.status_code}")
                return []
            ips = resp.json().get("ips", [])
            return [ProviderResult(ip=ip["ip"], resource_id=str(ip["id"]),
                                   region=ip.get("availability_zone", ""), raw=ip)
                    for ip in ips if ip.get("id") and ip.get("ip")]
        except Exception as exc:
            log_debug(f"[Timeweb] list_ips error: {exc}")
            return []

    def create_ip(self, region: str) -> ProviderResult:
        """Allocate a single Floating IP.

        Args:
            region: Availability zone identifier (e.g. "spb-2").

        Returns:
            ProviderResult with the allocated IP.

        Raises:
            DailyLimitError: If daily creation limit is exceeded.
            PermissionError: If account has no balance.
            RuntimeError: On rate limit or unexpected errors.
        """
        url = f"{self.BASE}/floating-ips"
        payload = {
            "availability_zone": region,
            "is_ddos_guard": False,
        }

        if self.session is None: raise RuntimeError("Вызовите init_session() перед create")
        resp = self.session.post(url, json=payload, timeout=self.timeout)

        # 429 — rate limit
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "?")
            raise RuntimeError(
                f"Rate limit (429) retry_after={retry_after}"
            )

        # 403 — проверяем конкретный error_code
        if resp.status_code == 403:
            self._handle_403(resp)

        # Другие ошибки
        if resp.status_code not in (200, 201):
            raise RuntimeError(
                f"Timeweb HTTP {resp.status_code}: {resp.text[:300]}"
            )

        # Парсим ответ
        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError(f"Timeweb: невалидный JSON: {exc}") from exc

        ip_data = data.get("ip", {})
        ip_addr = ip_data.get("ip", "")
        ip_id = str(ip_data.get("id", ""))
        az = ip_data.get("availability_zone", region)

        if not ip_addr or not ip_id:
            raise RuntimeError(f"Timeweb: неполный ответ: {data}")

        return ProviderResult(
            ip=ip_addr,
            resource_id=ip_id,
            region=az,
            raw=ip_data,
        )

    def _handle_403(self, resp) -> None:
        """Parse 403 response and raise the appropriate exception.

        Args:
            resp: HTTP response object.

        Raises:
            DailyLimitError: If daily limit exceeded.
            PermissionError: If no balance.
            RuntimeError: For other 403 errors.
        """
        try:
            data = resp.json()
        except ValueError:
            raise PermissionError(
                f"Timeweb 403: {resp.text[:200]}"
            )

        error_code = data.get("error_code", "")
        message = data.get("message", resp.text[:200])

        if error_code == "daily_limit_exceeded":
            details = data.get("details", {})
            resume_at = details.get("available_date_for_creation", "")
            log_warn(
                f"[Timeweb] Дневной лимит исчерпан. "
                f"Возобновление: {resume_at}"
            )
            raise DailyLimitError(
                f"Timeweb: дневной лимит ({message})",
                resume_at=resume_at,
            )

        if error_code == "no_balance_for_month":
            log_warn(
                f"[Timeweb] Баланс ниже порога для месяца. "
                f"Ожидание 1 час (баланс может быть достаточен, но Timeweb блокирует)."
            )
            raise DailyLimitError(
                f"Timeweb: баланс ниже порога ({message})",
                resume_at="",  # нет конкретного времени — ждём 1 час
            )

        raise RuntimeError(
            f"Timeweb 403 [{error_code}]: {message}"
        )

    def delete_ip(self, resource_id: str) -> None:
        """Release a Floating IP.

        Args:
            resource_id: Timeweb floating IP numeric ID as string.
        """
        url = f"{self.BASE}/floating-ips/{resource_id}"
        if self.session is None: raise RuntimeError("Сессия не инициализирована")

        resp = self.session.delete(url, timeout=self.timeout)

        if resp.status_code not in (200, 204):
            log_err(
                f"[Timeweb] DELETE {resource_id}: HTTP {resp.status_code}"
            )
            raise RuntimeError(
                f"Timeweb DELETE {resp.status_code}: {resp.text[:200]}"
            )
        log_debug(f"[Timeweb] Удалён {resource_id}")
