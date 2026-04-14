"""Terminal UI elements for IP Hunter."""

import sys
import time

_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

# ANSI
_R = "\033[0m" if _TTY else ""
_B = "\033[1m" if _TTY else ""
_DIM = "\033[2m" if _TTY else ""
_GREEN = "\033[32m" if _TTY else ""
_CYAN = "\033[36m" if _TTY else ""
_YELLOW = "\033[33m" if _TTY else ""
_RED = "\033[31m" if _TTY else ""
_MAG = "\033[35m" if _TTY else ""
_BG_GREEN = "\033[42m" if _TTY else ""
_WHITE = "\033[37m" if _TTY else ""


def banner() -> None:
    """Print the IP Hunter startup banner."""
    lines = [
        "╔═══════════════════════════════════════════╗",
        "║   🔍  IP Hunter v2.1 — Parallel Edition   ║",
        "║   MegaFon peering subnet finder           ║",
        "║   [no rate limiter, sync delete, v11 logic]║",
        "╚═══════════════════════════════════════════╝",
    ]
    print()
    for line in lines:
        print(f"  {_CYAN}{_B}{line}{_R}")
    print()


def found_banner(ip: str, provider: str, region: str, subnet: str,
                 attempt: int, elapsed: float) -> None:
    """Print a prominent found-IP banner.

    Args:
        ip: Found IP address.
        provider: Provider name.
        region: Region where IP was found.
        subnet: Matching subnet CIDR.
        attempt: Attempt number when found.
        elapsed: Seconds elapsed since start.
    """
    elapsed_str = _format_duration(elapsed)
    print()
    print(f"  {_BG_GREEN}{_B} ★★★  НАЙДЕН ЦЕЛЕВОЙ IP  ★★★ {_R}")
    print(f"  {_GREEN}{_B}IP:       {ip}{_R}")
    print(f"  {_GREEN}Подсеть:  {subnet}{_R}")
    print(f"  {_GREEN}Провайдер:{_R} {provider} ({region})")
    print(f"  {_GREEN}Попытка:  {_R}#{attempt}  |  Время: {elapsed_str}")
    print(f"  {_BG_GREEN}{_B} {'═' * 28} {_R}")
    print()


def print_stats(state: "SharedState") -> None:
    """Print final statistics table.

    Args:
        state: SharedState instance with collected stats.
    """
    elapsed = time.time() - state.start_time
    elapsed_str = _format_duration(elapsed)
    speed = state.global_attempt / elapsed if elapsed > 0 else 0

    print()
    print(f"  {_CYAN}{_B}{'═' * 50}{_R}")
    print(f"  {_CYAN}{_B}  Итоговая статистика{_R}")
    print(f"  {_CYAN}{'─' * 50}{_R}")
    print(f"  {_GREEN}Найдено IP:    {_B}{state.total_found}{_R}")
    print(f"  {_WHITE}Всего попыток: {state.global_attempt}{_R}")
    print(f"  {_WHITE}Удалено IP:    {state.total_deleted}{_R}")
    print(f"  {_RED}Ошибок:        {state.total_errors}{_R}")
    print(f"  {_WHITE}Скорость:      {speed:.1f} попыток/с{_R}")
    print(f"  {_WHITE}Время:         {elapsed_str}{_R}")

    if state.by_provider:
        print(f"\n  {_CYAN}{'─' * 50}{_R}")
        print(f"  {_B}  Разбивка по провайдерам{_R}")
        print(f"  {_DIM}  {'Провайдер':<15} {'Попытки':>8} {'Найдено':>8} {'Ошибки':>8} {'Удалено':>8}{_R}")
        for name, stats in sorted(state.by_provider.items()):
            att = stats.get("attempts", 0)
            fnd = stats.get("found", 0)
            err = stats.get("errors", 0)
            dlt = stats.get("deleted", 0)
            fnd_c = f"{_GREEN}{_B}{fnd}{_R}" if fnd > 0 else str(fnd)
            err_c = f"{_RED}{err}{_R}" if err > 0 else str(err)
            print(f"  {_MAG}  {name:<15}{_R} {att:>8} {fnd_c:>8} {err_c:>8} {dlt:>8}")

    print(f"  {_CYAN}{_B}{'═' * 50}{_R}")

    if state.found_ips:
        print(f"\n  {_GREEN}{_B}Найденные IP:{_R}")
        for entry in state.found_ips:
            print(f"    {_GREEN}●{_R} {entry['ip']} — {entry['provider']}:{entry['region']} "
                  f"∈ {entry.get('subnet', '?')}")
    print()


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration string."""
    s = int(seconds)
    if s < 60:
        return f"{s}с"
    if s < 3600:
        return f"{s // 60}м {s % 60}с"
    h = s // 3600
    m = (s % 3600) // 60
    return f"{h}ч {m}м {s % 60}с"
