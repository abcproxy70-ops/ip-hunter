"""Worker thread — один поток на провайдера.

Логика из v11 монолита:
- Selectel batch: create_ip_batch → проверить каждый IP → синхронно удалить ненужные
- Timeweb/Regru: create_ip → проверить → синхронно удалить
- При 429: sleep 60с и повторить (НЕ снижать RPM)
- При 409/quota: sleep 3с
- При PermissionError: отключить аккаунт
- При DailyLimitError: ждать до reset time
- Circuit breaker: 5 ошибок подряд → пауза 120с
- Без rate limiter — только естественная задержка от create/delete
"""

import random
import time
import threading
from datetime import datetime, timezone

import requests

from ip_hunter.logger import log_debug, log_err, log_info, log_ok, log_warn, log_attempt
from ip_hunter.providers.base import BaseProvider, DailyLimitError, ProviderResult
from ip_hunter.providers.selectel import SelectelProvider
from ip_hunter.rate_limiter import AdaptiveRateLimiter
from ip_hunter.state import SharedState
from ip_hunter.subnets import fast_match
from ip_hunter.telegram import send_telegram
from ip_hunter.ui import found_banner
from ipaddress import IPv4Network

_shutdown: bool = False


def request_shutdown() -> None:
    global _shutdown
    _shutdown = True


def is_shutdown() -> bool:
    return _shutdown


def join_pending_deletes(timeout: float = 30.0) -> None:
    """No-op — удаления теперь синхронные."""
    pass


def backoff_delay(errors: int, base: float = 2.0, cap: float = 60.0) -> float:
    return min(base * (2 ** errors), cap) * random.uniform(0.7, 1.3)


def _interruptible_sleep(seconds: float, step: float = 30.0) -> None:
    """Sleep в чанках с проверкой _shutdown."""
    deadline = time.time() + seconds
    while time.time() < deadline and not _shutdown:
        time.sleep(min(step, max(0.01, deadline - time.time())))


def _process_result(
    result: ProviderResult, subnet_set: set[IPv4Network],
    provider: BaseProvider, cfg: dict, state: SharedState,
    region: str, n: int, thread_name: str, thread_label: str, label: str,
) -> bool:
    """Проверяет IP на совпадение с подсетями. True если найден."""
    matched = fast_match(result.ip, subnet_set)

    if matched:
        is_new = state.add_found(
            ip=result.ip, provider=provider.name, region=region,
            subnet=matched, resource_id=result.resource_id,
            thread_label=thread_label,
        )
        if is_new:
            elapsed = time.time() - state.start_time
            elapsed_str = str(int(elapsed)) + "с"
            found_banner(result.ip, provider.name, region, matched, n, elapsed)

            _tg_notify(cfg,
                f"✅ <b>IP найден!</b> (#{state.total_found})\n\n"
                f"🏢 Провайдер: <code>{provider.name} {label}</code>\n"
                f"🌐 IP: <code>{result.ip}</code>\n"
                f"📋 ID: <code>{result.resource_id}</code>\n"
                f"🗺 Регион: <code>{region}</code>\n"
                f"🎯 Подсеть: <code>{matched}</code>\n"
                f"🔢 Попытка: #{n}\n"
                f"⏱ Время: {elapsed_str}\n"
                f"▶️ IP сохранён, продолжаю поиск"
            )
            log_ok(f"{thread_name} IP сохранён, продолжаю (найдено: {state.total_found})")
        return True

    # Мусорный IP — лог + уведомление в Telegram с полной информацией
    log_attempt(n, provider.name, region, result.ip, label)

    _tg_notify(cfg,
        f"❌ #{n} <b>мусор</b>\n"
        f"🏢 <code>{provider.name} {label}</code>\n"
        f"🌐 <code>{result.ip}</code>\n"
        f"📋 ID: <code>{result.resource_id}</code>\n"
        f"🗺 Регион: <code>{region}</code>"
    )
    return False


def provider_worker(
    provider: BaseProvider,
    subnet_set: set[IPv4Network],
    cfg: dict,
    state: SharedState,
    limiter: AdaptiveRateLimiter,  # не используется, но сохраняем сигнатуру
) -> None:
    """
    Основной цикл работы провайдера. Логика из v11.

    Selectel batch: create_ip_batch → проверить → синхронно удалить
    Timeweb/Regru: create_ip → проверить → синхронно удалить
    """
    global _shutdown

    label = ""
    if hasattr(provider, 'current_account_label'):
        label = provider.current_account_label
    thread_name = f"[{provider.name.upper()} {label}]"
    thread_label = f"{provider.name}:{label}"

    cb_threshold = cfg.get("circuit_breaker_threshold", 5)
    cb_cooldown = cfg.get("circuit_breaker_cooldown", 120)

    # Weighted region tracking
    region_hits: dict[str, int] = {}

    def pick_region() -> str:
        regions = provider.get_regions()
        if not region_hits or random.random() < 0.3:
            return random.choice(regions)
        total = sum(region_hits.get(r, 0) for r in regions)
        if total == 0:
            return random.choice(regions)
        weights = [region_hits.get(r, 0) + 1 for r in regions]
        return random.choices(regions, weights=weights, k=1)[0]

    # Batch config
    is_sel = isinstance(provider, SelectelProvider)
    batch_sz = getattr(provider, 'batch_size', 1) if is_sel else 1
    use_batch = is_sel and batch_sz > 1

    # Очистка мусорных IP перед стартом — освобождаем квоту
    _cleanup_stale_ips(provider, subnet_set, state, thread_name, thread_label)

    mode_str = f" (batch={batch_sz})" if batch_sz > 1 else ""
    log_info(f"{thread_name} Старт{mode_str}")

    while not _shutdown:
        region = pick_region()
        regional_attempts = 0
        max_regional = min(cfg.get("attempts_per_provider", 150), 50)

        log_info(f"{thread_name} → {region}{mode_str}")

        while regional_attempts < max_regional and not _shutdown:
            n = state.inc_attempt(thread_label)
            regional_attempts += 1

            try:
                # ── Selectel batch mode ──
                if use_batch and batch_sz > 1:
                    results = provider.create_ip_batch(region, batch_sz)
                    provider.errors_in_row = 0

                    to_delete = []
                    for res in results:
                        if not res.ip or not res.resource_id:
                            continue
                        found = _process_result(
                            res, subnet_set, provider, cfg, state,
                            region, n, thread_name, thread_label, label,
                        )
                        if found:
                            region_hits[region] = region_hits.get(region, 0) + 1
                        else:
                            to_delete.append(res.resource_id)

                    # Синхронное удаление (как в v11)
                    for rid in to_delete:
                        if _shutdown:
                            break
                        try:
                            provider.delete_ip(rid)
                            state.inc_deleted(thread_label)
                        except Exception as de:
                            log_debug(f"{thread_name} Ошибка удаления: {de}")

                # ── Обычный режим (Timeweb, Reg.ru, Selectel batch=1) ──
                else:
                    result = provider.create_ip(region)
                    provider.errors_in_row = 0

                    if not result.ip or not result.resource_id:
                        state.inc_errors(thread_label)
                        log_debug(f"{thread_name} Неполный ответ")
                        continue

                    found = _process_result(
                        result, subnet_set, provider, cfg, state,
                        region, n, thread_name, thread_label, label,
                    )
                    if found:
                        region_hits[region] = region_hits.get(region, 0) + 1
                    else:
                        # Синхронное удаление (как в v11)
                        try:
                            provider.delete_ip(result.resource_id)
                            state.inc_deleted(thread_label)
                        except Exception as de:
                            log_debug(f"{thread_name} Ошибка удаления: {de}")
                            time.sleep(random.uniform(2.0, 4.0))

            except PermissionError as e:
                log_err(f"{thread_name} {e}")
                log_err(f"{thread_name} Отключаю провайдера")
                # Блокируем аккаунт чтобы не пытаться при перезапуске
                state.mark_account_blocked(
                    provider.name,
                    {"extra": provider.cfg, "token": provider.cfg.get("token", "")},
                )
                _tg_notify(cfg, f"🚫 {thread_name} отключён: {e}")
                return

            except DailyLimitError as e:
                resume = e.resume_at
                log_warn(f"{thread_name} {e}")
                _tg_notify(cfg, f"⏸ {thread_name}: суточный лимит\nСброс: {resume}")

                if resume:
                    try:
                        resume_dt = datetime.fromisoformat(resume.replace("Z", "+00:00"))
                        now_utc = datetime.now(timezone.utc)
                        wait_secs = (resume_dt - now_utc).total_seconds()
                        if wait_secs > 0:
                            wait_mins = int(wait_secs / 60) + 1
                            log_info(f"{thread_name} Жду ~{wait_mins} мин до сброса")
                            _interruptible_sleep(wait_secs)
                            if not _shutdown:
                                log_ok(f"{thread_name} Лимит сброшен, продолжаю")
                                provider.errors_in_row = 0
                            break
                    except (ValueError, TypeError):
                        pass
                log_info(f"{thread_name} Жду 1 час до сброса...")
                _interruptible_sleep(3600)
                break

            except requests.ConnectionError as e:
                state.inc_errors(thread_label)
                provider.errors_in_row += 1
                log_debug(f"{thread_name} Соединение разорвано: {e}")
                time.sleep(random.uniform(2.0, 5.0))

                if provider.errors_in_row >= cb_threshold:
                    log_warn(f"{thread_name} Circuit breaker: {provider.errors_in_row} ошибок → пауза {cb_cooldown}с")
                    _tg_notify(cfg,
                        f"⚡ {thread_name}: circuit breaker ({provider.errors_in_row} ошибок)\nПауза: {cb_cooldown}с"
                    )
                    _interruptible_sleep(cb_cooldown)
                    provider.errors_in_row = 0

            except requests.Timeout as e:
                state.inc_errors(thread_label)
                provider.errors_in_row += 1
                log_debug(f"{thread_name} Таймаут: {e}")
                time.sleep(random.uniform(3.0, 8.0))

                if provider.errors_in_row >= cb_threshold:
                    log_warn(f"{thread_name} Circuit breaker: {provider.errors_in_row} таймаутов → пауза {cb_cooldown}с")
                    _interruptible_sleep(cb_cooldown)
                    provider.errors_in_row = 0

            except RuntimeError as e:
                state.inc_errors(thread_label)
                err_msg = str(e)
                if "(429)" in err_msg:
                    # ── При 429: sleep 60с и повторить (НЕ снижать RPM) ──
                    provider.errors_in_row += 1
                    log_warn(f"{thread_name} Rate limit (429) #{provider.errors_in_row} → пауза 60с")
                    time.sleep(60.0)
                    continue
                elif "(409)" in err_msg or "quota" in err_msg.lower():
                    log_warn(f"{thread_name} Квота — жду 3с")
                    time.sleep(3.0)
                else:
                    provider.errors_in_row += 1
                    bo = backoff_delay(provider.errors_in_row, cap=30.0)
                    log_warn(f"{thread_name} {e} → бэкофф {bo:.1f}с")
                    time.sleep(bo)

            except Exception as e:
                state.inc_errors(thread_label)
                provider.errors_in_row += 1
                log_warn(f"{thread_name} Ошибка: {e}")
                time.sleep(backoff_delay(provider.errors_in_row))

            # Смена региона каждые ~5-10 попыток
            if regional_attempts % random.randint(5, 10) == 0:
                region = pick_region()

    log_info(f"{thread_name} Поток завершён")


def _tg_notify(cfg: dict, text: str) -> None:
    t = cfg.get("telegram_bot_token", "")
    a = cfg.get("telegram_admin_id", "")
    if t and a:
        send_telegram(t, a, text)


def _cleanup_stale_ips(provider: BaseProvider, subnet_set: set[IPv4Network],
                       state: SharedState, thread_name: str, thread_label: str) -> None:
    """Удалить все мусорные floating IP при старте — освободить квоту."""
    try:
        existing = provider.list_ips()
    except Exception as exc:
        log_warn(f"{thread_name} list_ips ошибка: {exc}")
        return
    if not existing:
        log_info(f"{thread_name} Мусорных IP нет (list_ips: 0)")
        return

    # Все IP — мусорные (не совпадают с целевой подсетью) — удаляем
    stale = [ip for ip in existing if not fast_match(ip.ip, subnet_set)]
    target = [ip for ip in existing if fast_match(ip.ip, subnet_set)]

    if target:
        log_info(f"{thread_name} Найдено {len(target)} целевых IP — НЕ удаляем:")
        for ip in target:
            log_ok(f"{thread_name}   {ip.ip} (подсеть совпала)")

    if not stale:
        log_info(f"{thread_name} Мусорных IP нет ({len(existing)} активных, {len(target)} целевых)")
        return

    log_info(f"{thread_name} Удаляем {len(stale)} мусорных IP из {len(existing)}...")
    deleted = 0
    for ip in stale:
        if _shutdown:
            break
        try:
            provider.delete_ip(ip.resource_id)
            state.inc_deleted(thread_label)
            deleted += 1
        except Exception as exc:
            log_debug(f"{thread_name} Ошибка удаления {ip.ip}: {exc}")
        time.sleep(0.5)
    log_ok(f"{thread_name} Очистка: удалено {deleted}/{len(stale)}")
