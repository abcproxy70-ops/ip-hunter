"""IP Hunter CLI entrypoint."""

import signal
import sys
import time
from threading import Thread
from typing import Optional

from ip_hunter.config import Config, interactive_setup
from ip_hunter.logger import (
    _close_log_file, _init_log_file, log_debug, log_err, log_info, log_warn, set_debug,
)
from ip_hunter.providers import PROVIDERS
from ip_hunter.providers.base import BaseProvider
from ip_hunter.proxy import check_proxy, parse_proxy
from ip_hunter.rate_limiter import AdaptiveRateLimiter
from ip_hunter.state import SharedState
from ip_hunter.state import _extract_account_id, save_blocked
from ip_hunter.subnets import PROVIDER_SUBNETS, parse_subnets
from ip_hunter.telegram import send_telegram
from ip_hunter.ui import banner, print_stats
from ip_hunter.worker import is_shutdown, join_pending_deletes, provider_worker, request_shutdown

_in_main_loop = False


def _handle_signal(signum, frame) -> None:
    """Handle SIGINT/SIGTERM — request graceful shutdown."""
    if not _in_main_loop:
        sys.exit(1)
    log_warn("\n⛔ Получен сигнал завершения, останавливаем воркеры...")
    request_shutdown()


def _build_providers(cfg: Config) -> list[tuple[BaseProvider, dict, str]]:
    """Build provider instances from config, including extra accounts.

    Returns list of (provider_instance, flat_cfg_dict, proxy_str).
    """
    result: list[tuple[BaseProvider, dict, str]] = []

    for name, pcls in PROVIDERS.items():
        pcfg = getattr(cfg, name, {})
        if not pcfg.get("enabled"):
            continue
        extra = pcfg.get("extra", {})
        proxy_str = getattr(cfg, f"proxy_{name}", "") or cfg.proxy

        # Основной аккаунт
        accounts = [_make_account_cfg(name, pcfg, extra, label_suffix="")]
        # Extra accounts
        extras_key = "extra_accounts" if name != "timeweb" else "extra_tokens"
        extras = extra.get(extras_key, [])
        for i, ex in enumerate(extras):
            if name == "timeweb":
                acc = _make_timeweb_extra(pcfg, extra, ex, i + 2, len(extras) + 1)
            else:
                acc = _make_extra_account(name, pcfg, extra, ex, i + 2, len(extras) + 1)
            accounts.append(acc)

        # Нумеруем если > 1
        total = len(accounts)
        for idx, acc in enumerate(accounts):
            if total > 1:
                acc["label"] = f"{acc.get('label', name)} акк#{idx+1}/{total}"
            result.append((pcls, acc, proxy_str))

    return result


def _make_account_cfg(name: str, pcfg: dict, extra: dict, label_suffix: str) -> dict:
    """Build flat config dict for main account."""
    acc: dict = {"label": name + label_suffix}
    acc.update(extra)
    if name == "selectel":
        acc["token"] = pcfg.get("token", "")
        acc["regions"] = extra.get("regions", ["ru-2", "ru-3"])
        acc["base_url"] = extra.get("api_base", "https://api.selectel.ru/vpc/resell/")
    elif name == "timeweb":
        acc["token"] = pcfg.get("token", "")
        acc["regions"] = extra.get("availability_zones", ["spb-2", "spb-3"])
    elif name == "regru":
        acc["token"] = pcfg.get("token", "")
        acc["regions"] = [extra.get("region", "msk1")]
    return acc


def _make_extra_account(name: str, pcfg: dict, base_extra: dict,
                        ex: dict, num: int, total: int) -> dict:
    """Build flat config for an extra account (selectel/regru)."""
    merged = {**base_extra, **ex}
    acc: dict = {"label": name}
    acc.update(merged)
    if name == "selectel":
        acc["regions"] = merged.get("regions", base_extra.get("regions", ["ru-2", "ru-3"]))
        acc["base_url"] = merged.get("api_base", base_extra.get("api_base",
                          "https://api.selectel.ru/vpc/resell/"))
    elif name == "regru":
        acc["regions"] = [merged.get("region", base_extra.get("region", "msk1"))]
    return acc


def _make_timeweb_extra(pcfg: dict, base_extra: dict, token_str: str,
                        num: int, total: int) -> dict:
    """Build flat config for an extra Timeweb token."""
    acc: dict = {"label": "timeweb"}
    acc.update(base_extra)
    acc["token"] = token_str
    acc["regions"] = base_extra.get("availability_zones", ["spb-2", "spb-3"])
    return acc


def _check_socks_deps(cfg: Config) -> None:
    """Check if PySocks is installed when SOCKS proxy is configured."""
    all_proxies = [cfg.proxy, cfg.proxy_selectel, cfg.proxy_timeweb, cfg.proxy_regru]
    needs_socks = any("socks" in p.lower() for p in all_proxies if p)
    if not needs_socks:
        return
    try:
        import socks  # noqa: F401
    except ImportError:
        log_err(
            "SOCKS-прокси настроен, но PySocks не установлен!\n"
            "  Установите: pip install PySocks requests[socks]"
        )
        sys.exit(1)


def main() -> None:
    """Main entrypoint."""
    global _in_main_loop

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if "--debug" in sys.argv:
        set_debug(True)

    banner()

    # Загрузка конфига
    cfg = Config.load()

    any_enabled = any(
        getattr(cfg, n, {}).get("enabled", False) for n in PROVIDERS
    )
    if "--setup" in sys.argv or not any_enabled:
        if not sys.stdin.isatty():
            log_err("Нет активных провайдеров. Запустите с --setup в интерактивном режиме.")
            sys.exit(1)
        cfg = interactive_setup(cfg)

    _init_log_file(cfg.log_file)

    # Проверка SOCKS-зависимостей
    _check_socks_deps(cfg)

    # Прокси
    global_proxy = parse_proxy(cfg.proxy) if cfg.proxy else None
    if global_proxy:
        log_info("Проверяем глобальный прокси...")
        if not check_proxy(global_proxy):
            log_warn("Глобальный прокси не работает, продолжаем без него")
            global_proxy = None

    # Создание провайдеров
    provider_specs = _build_providers(cfg)
    if not provider_specs:
        log_err("Нет активных провайдеров. Запустите с --setup.")
        sys.exit(1)

    state = SharedState()

    # --reset-found / --reset-blocked
    if "--reset-found" in sys.argv:
        log_info("Сброс найденных IP")
        state.save_found_ips([])
    elif "--reset-blocked" in sys.argv:
        log_info("Сброс заблокированных аккаунтов")
        save_blocked(set())
    else:
        prev = state.load_found_ips()
        if prev:
            state.found_ips = prev
            state._found_set = {e["ip"] for e in prev}
            log_info(f"Загружено {len(prev)} ранее найденных IP")

    # Подсети
    subnet_sets: dict[str, set] = {}
    for name in PROVIDERS:
        custom = cfg.custom_subnets.get(name, "")
        raw = custom if custom else PROVIDER_SUBNETS.get(name, "")
        subnet_sets[name] = parse_subnets(raw) if raw else set()

    # Инициализация провайдеров
    initialized: list[tuple[BaseProvider, dict, str]] = []  # (provider, acc_cfg, proxy_key)
    proxy_groups: dict[str, int] = {}

    for pcls, acc_cfg, proxy_str in provider_specs:
        proxy_cfg = parse_proxy(proxy_str) if proxy_str else global_proxy
        provider_name = acc_cfg.get("label", "?").split()[0]

        # Пропуск заблокированных
        aid = _extract_account_id(provider_name, {"extra": acc_cfg, "token": acc_cfg.get("token", "")})
        if state.is_account_blocked(provider_name, aid):
            log_warn(f"Пропуск заблокированного: {acc_cfg.get('label', '?')}")
            continue

        # Captcha API key
        acc_cfg.setdefault("captcha_api_key", cfg.captcha_api_key)

        try:
            p = pcls(cfg=acc_cfg, timeout=cfg.timeouts, proxy=proxy_cfg)
            p.init_session()
        except Exception as exc:
            # Fallback: если прокси не работает — попробовать без прокси
            if proxy_cfg:
                log_warn(f"Инициализация {acc_cfg.get('label', '?')} через прокси не удалась, "
                         f"пробуем напрямую: {exc}")
                try:
                    p = pcls(cfg=acc_cfg, timeout=cfg.timeouts, proxy=None)
                    p.init_session()
                    proxy_str = ""  # для RPM считаем как "direct"
                except Exception as exc2:
                    log_err(f"Ошибка инициализации {acc_cfg.get('label', '?')} (и без прокси): {exc2}")
                    continue
            else:
                log_err(f"Ошибка инициализации {acc_cfg.get('label', '?')}: {exc}")
                continue

        pk = proxy_str or "direct"
        proxy_groups[pk] = proxy_groups.get(pk, 0) + 1
        initialized.append((p, acc_cfg, pk))

    if not initialized:
        log_err("Ни один провайдер не инициализирован.")
        sys.exit(1)

    # Назначаем limiter'ы одним проходом — proxy_groups уже финальные
    active: list[tuple[BaseProvider, dict, AdaptiveRateLimiter]] = []
    for p, acc_cfg, pk in initialized:
        n_on_proxy = proxy_groups.get(pk, 1)
        effective_rpm = max(4, cfg.rpm_limit // n_on_proxy)
        limiter = AdaptiveRateLimiter(rpm_max=effective_rpm)
        active.append((p, acc_cfg, limiter))
        log_info(f"✓ {acc_cfg.get('label', '?')} (rpm={effective_rpm})")

    flat_cfg = {
        "attempts_per_provider": cfg.attempts_per_provider,
        "circuit_breaker_threshold": cfg.circuit_breaker_threshold,
        "circuit_breaker_cooldown": cfg.circuit_breaker_cooldown,
        "telegram_bot_token": cfg.telegram_bot_token,
        "telegram_admin_id": cfg.telegram_admin_id,
    }

    # Запуск потоков
    threads: list[Thread] = []
    _in_main_loop = True

    for i, (p, acc_cfg, limiter) in enumerate(active):
        sset = subnet_sets.get(p.name, set())
        t = Thread(
            target=provider_worker,
            args=(p, sset, flat_cfg, state, limiter),
            name=f"worker-{acc_cfg.get('label', p.name)}",
            daemon=True,
        )
        t.start()
        threads.append(t)
        if i < len(active) - 1:
            time.sleep(3.0)

    log_info(f"Запущено {len(threads)} воркеров")

    # Main loop
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=1.0)
            if is_shutdown():
                break
    except KeyboardInterrupt:
        request_shutdown()

    # Ожидание завершения
    for t in threads:
        t.join(timeout=10.0)

    # Дождаться фоновых удалений
    log_info("Ожидание завершения фоновых удалений...")
    join_pending_deletes(timeout=30.0)

    for p, _, _ in active:
        p.close()

    _close_log_file()
    print_stats(state)

    # Telegram итог
    if cfg.telegram_bot_token and cfg.telegram_admin_id:
        elapsed = time.time() - state.start_time
        found_list = "\n".join(
            f"  {e['ip']} ({e['provider']}:{e['region']})" for e in state.found_ips
        ) or "  нет"
        send_telegram(cfg.telegram_bot_token, cfg.telegram_admin_id,
            f"📊 <b>IP Hunter завершён</b>\n"
            f"Найдено: {state.total_found}\n"
            f"Попыток: {state.global_attempt}\n"
            f"Время: {int(elapsed)}с\n{found_list}")


if __name__ == "__main__":
    main()
