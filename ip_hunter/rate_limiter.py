"""Автоадаптивный rate limiter — находит потолок сам по 429-ответам.

Не нужен rpm_limit в конфиге. Каждый аккаунт получает свой лимитер,
стартует с высокого RPM и снижается только при реальных 429.
"""

import threading
import time
from collections import deque

from ip_hunter.logger import log_debug


class AdaptiveRateLimiter:
    """Sliding window rate limiter с автоподстройкой.

    Логика:
    - Старт с rpm_start (по умолчанию 60 — агрессивно)
    - При 429: снижаем на 30%, запоминаем потолок
    - При серии успехов: медленно поднимаем обратно к потолку
    - Потолок (ceiling) = последний RPM до 429, не даём подняться выше
    """

    WINDOW_SEC: float = 60.0

    def __init__(self, rpm_start: int = 60) -> None:
        self._rpm: int = rpm_start
        self._ceiling: int = rpm_start  # потолок — снижается при 429
        self._lock = threading.Lock()
        self._timestamps: deque[float] = deque()
        self._success_count: int = 0

    @property
    def current_rpm(self) -> int:
        with self._lock:
            return self._rpm

    def _purge_old(self, now: float) -> None:
        """Убрать таймстампы старше окна."""
        cutoff = now - self.WINDOW_SEC
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def wait_if_needed(self, cost: int = 2) -> None:
        """Блокировать пока нет слотов в окне."""
        while True:
            with self._lock:
                now = time.monotonic()
                self._purge_old(now)
                if len(self._timestamps) + cost <= self._rpm:
                    for _ in range(cost):
                        self._timestamps.append(now)
                    return
                # Считаем сколько ждать
                if self._timestamps:
                    oldest = self._timestamps[0]
                    sleep_time = max(0.01, (oldest + self.WINDOW_SEC) - now + 0.05)
                else:
                    sleep_time = 0.1

            log_debug(f"[RateLimiter] Ожидание {sleep_time:.2f}с (rpm={self._rpm})")
            time.sleep(sleep_time)

    def on_success(self) -> None:
        """Успешный запрос — после 10 успехов поднимаем RPM на +2."""
        with self._lock:
            self._success_count += 1
            if self._success_count >= 10:
                old = self._rpm
                self._rpm = min(self._rpm + 2, self._ceiling)
                self._success_count = 0
                if self._rpm != old:
                    log_debug(f"[RateLimiter] RPM: {old} → {self._rpm}")

    def on_rate_limit(self) -> None:
        """429 получен — снижаем RPM, опускаем потолок."""
        with self._lock:
            old = self._rpm
            # Потолок = текущий RPM (мы были слишком агрессивны)
            self._ceiling = max(6, old - 1)
            # Снижаем на 30%
            self._rpm = max(6, int(self._rpm * 0.7))
            self._success_count = 0
            log_debug(f"[RateLimiter] 429! RPM: {old} → {self._rpm} (ceiling={self._ceiling})")
