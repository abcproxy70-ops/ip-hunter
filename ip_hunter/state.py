"""Thread-safe shared state and blocked accounts management."""

import json
import threading
import time
from typing import Optional

from ip_hunter.config import BLOCKED_FILE, FOUND_IPS_FILE
from ip_hunter.logger import log_debug


class SharedState:
    """Thread-safe shared state for parallel IP hunting."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.global_attempt: int = 0
        self.total_errors: int = 0
        self.total_deleted: int = 0
        self.by_provider: dict[str, dict[str, int]] = {}
        self.found_ips: list[dict] = []
        self.start_time: float = time.time()
        self._found_set: set[str] = set()
        self._blocked: set[str] = set()
        self._blocked_loaded: bool = False

    def inc_attempt(self, provider_name: str) -> int:
        """Increment global attempt counter and per-provider stats.

        Returns:
            New global attempt number.
        """
        with self._lock:
            self.global_attempt += 1
            n = self.global_attempt
            prov = self.by_provider.setdefault(provider_name, {
                "attempts": 0, "errors": 0, "found": 0, "deleted": 0,
            })
            prov["attempts"] += 1
            return n

    def inc_errors(self, provider_name: str = "") -> None:
        """Increment error counters."""
        with self._lock:
            self.total_errors += 1
            if provider_name and provider_name in self.by_provider:
                self.by_provider[provider_name]["errors"] += 1

    def inc_deleted(self, provider_name: str = "") -> None:
        """Increment deleted counters."""
        with self._lock:
            self.total_deleted += 1
            if provider_name and provider_name in self.by_provider:
                self.by_provider[provider_name]["deleted"] += 1

    def add_found(self, ip: str, provider: str, region: str,
                  subnet: str, resource_id: str, thread_label: str) -> bool:
        """Add a found IP with deduplication.

        Returns:
            True if this IP is new, False if duplicate.
        """
        with self._lock:
            if ip in self._found_set:
                return False
            self._found_set.add(ip)
            entry = {
                "ip": ip, "provider": provider, "region": region,
                "subnet": subnet, "resource_id": resource_id,
                "thread_label": thread_label, "found_at": time.time(),
            }
            self.found_ips.append(entry)
            if provider in self.by_provider:
                self.by_provider[provider]["found"] += 1
        # Сохраняем на диск ВНЕ лока
        self.save_found_ips(self.found_ips)
        return True

    @property
    def total_found(self) -> int:
        """Return total number of found IPs."""
        with self._lock:
            return len(self.found_ips)

    # ---- Persistence ----

    @staticmethod
    def save_found_ips(found_ips: list[dict]) -> None:
        """Save found IPs list to disk."""
        try:
            FOUND_IPS_FILE.write_text(
                json.dumps(found_ips, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as exc:
            log_debug(f"[State] Ошибка сохранения found_ips: {exc}")

    @staticmethod
    def load_found_ips() -> list[dict]:
        """Load found IPs from disk."""
        if not FOUND_IPS_FILE.exists():
            return []
        try:
            data = json.loads(FOUND_IPS_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError) as exc:
            log_debug(f"[State] Ошибка чтения found_ips: {exc}")
            return []

    # ---- Blocked accounts ----

    def _ensure_blocked_loaded(self) -> None:
        """Lazy-load blocked accounts from disk."""
        if not self._blocked_loaded:
            self._blocked = load_blocked()
            self._blocked_loaded = True

    def mark_account_blocked(self, provider: str, cfg: dict) -> None:
        """Mark an account as blocked based on provider-specific identifier."""
        identifier = _extract_account_id(provider, cfg)
        if not identifier:
            return
        key = f"{provider}:{identifier}"
        with self._lock:
            self._ensure_blocked_loaded()
            self._blocked.add(key)
        save_blocked(self._blocked)
        log_debug(f"[State] Заблокирован: {key}")

    def is_account_blocked(self, provider_name: str, identifier: str) -> bool:
        """Check if an account is blocked."""
        key = f"{provider_name}:{identifier}"
        with self._lock:
            self._ensure_blocked_loaded()
            return key in self._blocked


def _extract_account_id(provider: str, cfg: dict) -> str:
    """Extract unique account identifier from provider config."""
    extra = cfg.get("extra", {})
    if provider == "selectel":
        return extra.get("project_id", "") or cfg.get("token", "")[:16]
    if provider == "timeweb":
        token = cfg.get("token", "")
        return token[:16] if token else ""
    if provider == "regru":
        return extra.get("service_id", "") or extra.get("login", "")
    return ""


def load_blocked() -> set[str]:
    """Load blocked accounts set from disk."""
    if not BLOCKED_FILE.exists():
        return set()
    try:
        data = json.loads(BLOCKED_FILE.read_text(encoding="utf-8"))
        return set(data) if isinstance(data, list) else set()
    except (OSError, json.JSONDecodeError) as exc:
        log_debug(f"[State] Ошибка чтения blocked: {exc}")
        return set()


def save_blocked(blocked: set[str]) -> None:
    """Save blocked accounts set to disk."""
    try:
        BLOCKED_FILE.write_text(
            json.dumps(sorted(blocked), indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except OSError as exc:
        log_debug(f"[State] Ошибка сохранения blocked: {exc}")
