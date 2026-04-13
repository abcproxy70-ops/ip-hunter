"""Base provider interface for IP Hunter."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProviderResult:
    """Результат создания Floating IP."""

    ip: str
    resource_id: str
    region: str
    raw: dict = field(default_factory=dict)


class DailyLimitError(Exception):
    """Превышен дневной лимит провайдера."""

    def __init__(self, message: str, resume_at: str = "") -> None:
        super().__init__(message)
        self.resume_at = resume_at


class BaseProvider(ABC):
    """Abstract base for all hosting providers."""

    name: str = "base"

    def __init__(
        self,
        cfg: dict,
        timeout: tuple[int, int] = (10, 30),
        proxy: Optional[dict] = None,
    ) -> None:
        self.cfg = cfg
        self.timeout = timeout
        self.proxy = proxy
        self.session = None
        self.errors_in_row: int = 0

    @abstractmethod
    def init_session(self) -> None:
        """Initialize HTTP session with auth."""
        ...

    @abstractmethod
    def create_ip(self, region: str) -> ProviderResult:
        """Allocate a new Floating IP in the given region."""
        ...

    @abstractmethod
    def delete_ip(self, resource_id: str) -> None:
        """Release a previously allocated Floating IP."""
        ...

    @abstractmethod
    def get_regions(self) -> list[str]:
        """Return list of available region identifiers."""
        ...

    def close(self) -> None:
        """Close the underlying HTTP session."""
        if self.session:
            try:
                self.session.close()
            except Exception as exc:
                from ip_hunter.logger import log_debug
                log_debug(f"[{self.name}] Ошибка закрытия сессии: {exc}")
            self.session = None
