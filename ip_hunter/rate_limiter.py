"""Adaptive rate limiter with sliding window for API call throttling."""

import threading
import time
from collections import deque

from ip_hunter.logger import log_debug


class AdaptiveRateLimiter:
    """Thread-safe adaptive rate limiter using a 60-second sliding window.

    Увеличивает RPM после серии успехов, снижает при получении 429.
    sleep выполняется ВНЕ лока, чтобы не блокировать on_success/on_rate_limit.
    """

    WINDOW_SEC: float = 60.0
    SUCCESS_STREAK_THRESHOLD: int = 20

    def __init__(self, rpm_max: int = 20) -> None:
        self._rpm_max: int = rpm_max
        self._rpm: int = rpm_max
        self._lock = threading.Lock()
        self._timestamps: deque[float] = deque()
        self._success_streak: int = 0

    @property
    def current_rpm(self) -> int:
        """Return the current effective RPM limit."""
        with self._lock:
            return self._rpm

    def _purge_old(self, now: float) -> None:
        """Remove timestamps older than the sliding window (caller holds lock)."""
        cutoff = now - self.WINDOW_SEC
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def wait_if_needed(self, cost: int = 2) -> None:
        """Block until there is capacity in the sliding window.

        Args:
            cost: Number of request slots this call consumes.
        """
        while True:
            sleep_time = 0.0
            with self._lock:
                now = time.monotonic()
                self._purge_old(now)
                if len(self._timestamps) + cost <= self._rpm:
                    # Есть место — записываем таймстампы и выходим
                    for _ in range(cost):
                        self._timestamps.append(now)
                    return
                # Нужно подождать до освобождения слота
                if self._timestamps:
                    oldest = self._timestamps[0]
                    sleep_time = max(0.01, (oldest + self.WINDOW_SEC) - now + 0.05)
                else:
                    sleep_time = 0.1

            # Sleep ВНЕ лока
            log_debug(f"[RateLimiter] Ожидание {sleep_time:.2f}с (rpm={self._rpm})")
            time.sleep(sleep_time)

    def on_success(self) -> None:
        """Signal a successful request — may increase RPM after streak."""
        with self._lock:
            self._success_streak += 1
            if self._success_streak >= self.SUCCESS_STREAK_THRESHOLD:
                old_rpm = self._rpm
                self._rpm = min(self._rpm + 1, self._rpm_max)
                self._success_streak = 0
                if self._rpm != old_rpm:
                    log_debug(
                        f"[RateLimiter] RPM увеличен: {old_rpm} -> {self._rpm}"
                    )

    def on_rate_limit(self) -> None:
        """Signal a 429 response — decrease RPM aggressively."""
        with self._lock:
            old_rpm = self._rpm
            self._rpm = max(4, int(self._rpm * 0.7))
            self._success_streak = 0
            log_debug(
                f"[RateLimiter] 429! RPM снижен: {old_rpm} -> {self._rpm}"
            )

    def reset(self) -> None:
        """Reset limiter to initial state."""
        with self._lock:
            self._rpm = self._rpm_max
            self._timestamps.clear()
            self._success_streak = 0
