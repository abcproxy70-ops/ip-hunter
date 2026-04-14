"""Rate limiter stub — УБРАН полностью по требованию.

Вместо AdaptiveRateLimiter — пустая заглушка.
Логика при 429: sleep 60с прямо в worker.
"""


class AdaptiveRateLimiter:
    """No-op rate limiter stub. Все методы — пустышки."""

    def __init__(self, rpm_start: int = 60) -> None:
        pass

    def wait_if_needed(self, cost: int = 2) -> None:
        """Не ждём — никакого rate limiting."""
        pass

    def on_success(self) -> None:
        """Не отслеживаем успехи."""
        pass

    def on_rate_limit(self) -> None:
        """Не отслеживаем 429 — обработка в worker."""
        pass

    @property
    def current_rpm(self) -> int:
        return 0
