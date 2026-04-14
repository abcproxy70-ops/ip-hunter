"""Thread-safe colored logger with parallel file output."""

import os
import re
import sys
import threading
from datetime import datetime
from typing import IO, Optional

# ---------------------------------------------------------------------------
# ANSI-цвета (отключаются если stdout не TTY)
# ---------------------------------------------------------------------------

_IS_TTY: bool = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class _C:
    """ANSI color codes container."""

    RESET = "\033[0m" if _IS_TTY else ""
    BOLD = "\033[1m" if _IS_TTY else ""
    DIM = "\033[2m" if _IS_TTY else ""
    GREEN = "\033[32m" if _IS_TTY else ""
    YELLOW = "\033[33m" if _IS_TTY else ""
    RED = "\033[31m" if _IS_TTY else ""
    CYAN = "\033[36m" if _IS_TTY else ""
    MAGENTA = "\033[35m" if _IS_TTY else ""
    WHITE = "\033[37m" if _IS_TTY else ""
    BG_GREEN = "\033[42m" if _IS_TTY else ""
    BG_RED = "\033[41m" if _IS_TTY else ""


# ---------------------------------------------------------------------------
# Глобальное состояние
# ---------------------------------------------------------------------------

_log_lock = threading.Lock()
_log_file: Optional[IO[str]] = None
_debug_enabled: bool = False

# Regex для strip ANSI из файлового вывода
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def set_debug(enabled: bool) -> None:
    """Enable or disable debug-level output."""
    global _debug_enabled
    _debug_enabled = enabled


def is_debug() -> bool:
    """Return whether debug mode is active."""
    return _debug_enabled


# ---------------------------------------------------------------------------
# Файловый вывод
# ---------------------------------------------------------------------------


def _init_log_file(path: str) -> None:
    """Open a log file for writing (line-buffered, ANSI stripped).

    Args:
        path: Filesystem path for the log file.
    """
    global _log_file
    with _log_lock:
        if _log_file is not None:
            try:
                _log_file.close()
            except Exception as exc:
                sys.stderr.write(f"[logger] close error: {exc}\n")
        try:
            _log_file = open(path, "a", encoding="utf-8", buffering=1)  # line-buffered
        except OSError as exc:
            _log_file = None
            _write_console(
                f"{_C.RED}[!] Не удалось открыть лог-файл {path}: {exc}{_C.RESET}"
            )


def _close_log_file() -> None:
    """Close the current log file if open."""
    global _log_file
    with _log_lock:
        if _log_file is not None:
            try:
                _log_file.close()
            except Exception as exc:
                sys.stderr.write(f"[logger] close error: {exc}\n")
            _log_file = None


# ---------------------------------------------------------------------------
# Внутренние функции вывода
# ---------------------------------------------------------------------------


def _timestamp() -> str:
    """Return current timestamp string."""
    return datetime.now().strftime("%H:%M:%S")


def _write_console(line: str) -> None:
    """Write a line to stdout (thread-unsafe — caller must hold _log_lock or not care)."""
    try:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
    except Exception as exc:
        sys.stderr.write(f"[logger] console write error: {exc}\n")


def _write_file(line: str) -> None:
    """Write ANSI-stripped line to the log file (caller must hold _log_lock)."""
    if _log_file is not None:
        try:
            clean = _ANSI_RE.sub("", line)
            _log_file.write(clean + "\n")
        except Exception as exc:
            sys.stderr.write(f"[logger] file write error: {exc}\n")


def _emit(line: str) -> None:
    """Emit a formatted line to console and file under lock."""
    with _log_lock:
        _write_console(line)
        _write_file(line)


# ---------------------------------------------------------------------------
# Публичные функции логирования
# ---------------------------------------------------------------------------


def log_info(msg: str) -> None:
    """Log an informational message (cyan)."""
    _emit(f"{_C.DIM}{_timestamp()}{_C.RESET} {_C.CYAN}[i]{_C.RESET} {msg}")


def log_ok(msg: str) -> None:
    """Log a success message (green)."""
    _emit(f"{_C.DIM}{_timestamp()}{_C.RESET} {_C.GREEN}[✓]{_C.RESET} {msg}")


def log_warn(msg: str) -> None:
    """Log a warning message (yellow)."""
    _emit(f"{_C.DIM}{_timestamp()}{_C.RESET} {_C.YELLOW}[!]{_C.RESET} {msg}")


def log_err(msg: str) -> None:
    """Log an error message (red)."""
    _emit(f"{_C.DIM}{_timestamp()}{_C.RESET} {_C.RED}[✗]{_C.RESET} {msg}")


def log_debug(msg: str) -> None:
    """Log a debug message (dim, only if debug mode is enabled)."""
    if not _debug_enabled:
        return
    _emit(f"{_C.DIM}{_timestamp()} [D] {msg}{_C.RESET}")


def log_attempt(
    n: int,
    provider: str,
    region: str,
    ip: str,
    acct: str = "",
) -> None:
    """Log a Floating IP allocation attempt with details.

    Args:
        n: Attempt number.
        provider: Provider name (selectel, timeweb, regru).
        region: Region identifier.
        ip: Allocated IP address.
        acct: Account label (optional).
    """
    acct_str = f" [{acct}]" if acct else ""
    _emit(
        f"{_C.DIM}{_timestamp()}{_C.RESET} "
        f"{_C.MAGENTA}#{n:<5}{_C.RESET} "
        f"{_C.BOLD}{provider}{_C.RESET}:{region}{acct_str} → "
        f"{_C.WHITE}{ip}{_C.RESET}"
    )


def log_match(ip: str, subnet: str, provider: str) -> None:
    """Log a successful subnet match (bright green background).

    Args:
        ip: Matched IP address.
        subnet: Matching subnet CIDR.
        provider: Provider name.
    """
    _emit(
        f"\n{_C.BG_GREEN}{_C.BOLD} ★ MATCH ★ {_C.RESET} "
        f"{_C.GREEN}{_C.BOLD}{ip}{_C.RESET} ∈ {subnet} "
        f"({provider})\n"
    )


def log_separator() -> None:
    """Log a visual separator line."""
    _emit(f"{_C.DIM}{'─' * 60}{_C.RESET}")
