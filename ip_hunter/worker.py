"""Worker thread logic for parallel IP hunting."""

import random
import re
import threading
import time
from datetime import datetime, timezone

import requests

from ip_hunter.logger import log_debug, log_err, log_info, log_warn, log_attempt
from ip_hunter.providers.base import BaseProvider, DailyLimitError, ProviderResult
from ip_hunter.providers.selectel import SelectelProvider
from ip_hunter.rate_limiter import AdaptiveRateLimiter
from ip_hunter.state import SharedState
from ip_hunter.subnets import fast_match
from ip_hunter.telegram import send_telegram
from ip_hunter.ui import found_banner
from ipaddress import IPv4Network

_shutdown: bool = False
_pending_deletes: list[threading.Thread] = []
_pending_lock = threading.Lock()

def request_shutdown() -> None:
    """Signal all workers to stop."""
    global _shutdown
    _shutdown = True

def is_shutdown() -> bool:
    """Check if shutdown was requested."""
    return _shutdown

def join_pending_deletes(timeout: float = 30.0) -> None:
    """Wait for all pending async delete threads to finish."""
    with _pending_lock:
        threads = list(_pending_deletes)
    deadline = time.time() + timeout
    for t in threads:
        t.join(timeout=max(0.1, deadline - time.time()))
    with _pending_lock:
        _pending_deletes[:] = [t for t in _pending_deletes if t.is_alive()]
    alive = len(_pending_deletes)
    if alive:
        log_warn(f"[Worker] {alive} delete-потоков не завершились за {timeout}с")

def backoff_delay(errors: int, base: float = 2.0, cap: float = 60.0) -> float:
    """Calculate exponential backoff with jitter."""
    return min(base * (2 ** errors), cap) * random.uniform(0.7, 1.3)

def _interruptible_sleep(seconds: float, step: float = 30.0) -> None:
    """Sleep in chunks, checking _shutdown between them."""
    deadline = time.time() + seconds
    while time.time() < deadline and not _shutdown:
        time.sleep(min(step, max(0.01, deadline - time.time())))

def _delete_async(provider: BaseProvider, resource_id: str,
                  state: SharedState, thread_label: str = "",
                  max_retries: int = 2) -> None:
    """Delete IP/server in background thread with retry on 429/5xx."""
    label = thread_label or provider.name
    def _worker() -> None:
        for attempt in range(max_retries + 1):
            try:
                provider.delete_ip(resource_id)
                state.inc_deleted(label)
                return
            except Exception as exc:
                err = str(exc)
                retryable = "(429)" in err or "502" in err or "503" in err or "504" in err
                if attempt < max_retries and retryable:
                    log_debug(f"[{provider.name}] Delete retry {attempt+1} {resource_id}: {exc}")
                    time.sleep(2 * (attempt + 1))
                else:
                    log_err(f"[{provider.name}] Delete failed {resource_id}: {exc}")
                    return
    t = threading.Thread(target=_worker, daemon=True)
    with _pending_lock:
        # Чистим завершённые потоки
        _pending_deletes[:] = [x for x in _pending_deletes if x.is_alive()]
        _pending_deletes.append(t)
    t.start()

def _process_result(result: ProviderResult, subnet_set: set[IPv4Network],
                    provider: BaseProvider, cfg: dict, state: SharedState,
                    region: str, n: int, thread_name: str,
                    thread_label: str, label: str) -> bool:
    """Check IP against subnets; if matched, record and notify."""
    matched = fast_match(result.ip, subnet_set)
    if matched:
        elapsed = time.time() - state.start_time
        is_new = state.add_found(
            ip=result.ip, provider=provider.name, region=result.region,
            subnet=matched, resource_id=result.resource_id, thread_label=thread_label)
        if is_new:
            found_banner(result.ip, provider.name, result.region, matched, n, elapsed)
            _tg_notify(cfg, f"🎯 <b>НАЙДЕН IP</b>\n{result.ip} ∈ {matched}\n"
                       f"{provider.name}:{result.region}\nПопытка #{n}")
        return True
    log_attempt(n, provider.name, region, result.ip,
                getattr(provider, "current_account_label", ""))
    return False

def provider_worker(provider: BaseProvider, subnet_set: set[IPv4Network],
                    cfg: dict, state: SharedState,
                    limiter: AdaptiveRateLimiter) -> None:
    """Main worker loop for a single provider instance."""
    label = getattr(provider, "current_account_label", provider.name)
    thread_label = f"{provider.name}:{label}"
    thread_name = f"[{provider.name.upper()} {label}]"
    regions = provider.get_regions()
    if not regions:
        log_err(f"{thread_name} Нет регионов"); return
    max_attempts = cfg.get("attempts_per_provider", 150)
    cb_threshold = cfg.get("circuit_breaker_threshold", 5)
    cb_cooldown = cfg.get("circuit_breaker_cooldown", 120)
    is_sel = isinstance(provider, SelectelProvider)
    batch_sz = getattr(provider, "batch_size", 1) if is_sel else 1
    use_batch = is_sel and batch_sz > 1
    cost = 1  # 1 HTTP create = 1 слот; delete async — не считается

    region_hits: dict[str, int] = {r: 0 for r in regions}
    def pick_region() -> str:
        """Select region: 30% random, 70% weighted by hit count."""
        if random.random() < 0.3 or not any(region_hits.values()):
            return random.choice(regions)
        return random.choices(regions, [region_hits[r] + 1 for r in regions])[0]

    local_attempts, regional_counter = 0, 0
    region = pick_region()
    region_switch = random.randint(5, 10)
    log_info(f"{thread_name} Старт (регионы: {regions}, batch={batch_sz})")

    while not _shutdown and local_attempts < max_attempts:
        limiter.wait_if_needed(cost)
        if _shutdown: break
        n = state.inc_attempt(thread_label)
        local_attempts += 1; regional_counter += 1
        try:
            if use_batch:
                _do_selectel_batch(provider, subnet_set, cfg, state, regions,
                                   batch_sz, n, thread_name, thread_label, label, region_hits)
            else:
                _do_single(provider, subnet_set, cfg, state, region, n,
                           thread_name, thread_label, label, region_hits)
            provider.errors_in_row = 0; limiter.on_success()
        except PermissionError as exc:
            log_err(f"{thread_name} Доступ запрещён: {exc}")
            state.mark_account_blocked(provider.name, cfg)
            _tg_notify(cfg, f"🚫 {thread_name} заблокирован: {exc}"); return
        except DailyLimitError as exc:
            log_warn(f"{thread_name} Суточный лимит: {exc}")
            _tg_notify(cfg, f"⏸ {thread_name} суточный лимит: {exc}")
            _interruptible_sleep(_calc_daily_limit_wait(exc)); continue
        except requests.ConnectionError as exc:
            log_debug(f"{thread_name} ConnectionError: {exc}")
            state.inc_errors(thread_label); provider.errors_in_row += 1
            if provider.errors_in_row >= cb_threshold:
                _circuit_breaker(thread_name, provider, cfg, cb_cooldown)
            continue
        except requests.Timeout as exc:
            log_debug(f"{thread_name} Timeout: {exc}")
            state.inc_errors(thread_label); provider.errors_in_row += 1
            if provider.errors_in_row >= cb_threshold:
                _circuit_breaker(thread_name, provider, cfg, cb_cooldown)
            continue
        except RuntimeError as exc:
            state.inc_errors(thread_label)
            err = str(exc)
            if "JWT expired, cooldown" in err or "JWT не получен" in err:
                m = re.search(r'(\d+)', err)
                _interruptible_sleep(min((int(m.group(1)) if m else 300) + 10, 310))
                provider.errors_in_row = 0; continue
            if "(429)" in err:
                provider.errors_in_row += 1; limiter.on_rate_limit()
                ra = _extract_retry_after(err)
                _interruptible_sleep(min(max(ra, min(10 * provider.errors_in_row, 60)), 120))
                continue
            if "(409)" in err or "quota" in err.lower():
                _interruptible_sleep(3); continue
            provider.errors_in_row += 1
            _interruptible_sleep(backoff_delay(provider.errors_in_row, cap=30)); continue
        except Exception as exc:
            log_err(f"{thread_name} Неожиданная ошибка: {exc}")
            state.inc_errors(thread_label); provider.errors_in_row += 1
            _interruptible_sleep(backoff_delay(provider.errors_in_row, cap=30)); continue
        if regional_counter >= region_switch:
            region = pick_region(); regional_counter = 0
            region_switch = random.randint(5, 10)
    log_info(f"{thread_name} Завершён ({local_attempts} попыток)")

def _do_selectel_batch(provider, subnet_set, cfg, state, regions, batch_sz,
                       n, thread_name, thread_label, label, region_hits) -> None:
    """Execute Selectel multi-region batch create, async delete misses."""
    results = provider.create_ip_multi_region({r: batch_sz for r in regions})
    for res in results:
        if _process_result(res, subnet_set, provider, cfg, state,
                           res.region, n, thread_name, thread_label, label):
            region_hits[res.region] = region_hits.get(res.region, 0) + 1
        else:
            _delete_async(provider, res.resource_id, state, thread_label)

def _do_single(provider, subnet_set, cfg, state, region, n,
               thread_name, thread_label, label, region_hits) -> None:
    """Execute single IP create/check/async-delete cycle."""
    result = provider.create_ip(region)
    if _process_result(result, subnet_set, provider, cfg, state,
                       region, n, thread_name, thread_label, label):
        region_hits[region] = region_hits.get(region, 0) + 1
    else:
        _delete_async(provider, result.resource_id, state, thread_label)

def _tg_notify(cfg: dict, text: str) -> None:
    """Send telegram notification if configured."""
    t, a = cfg.get("telegram_bot_token", ""), cfg.get("telegram_admin_id", "")
    if t and a: send_telegram(t, a, text)

def _circuit_breaker(thread_name: str, provider: BaseProvider,
                     cfg: dict, cooldown: int) -> None:
    """Pause provider after too many consecutive errors."""
    log_warn(f"{thread_name} Circuit breaker: пауза {cooldown}с")
    _tg_notify(cfg, f"⚡ {thread_name} circuit breaker "
               f"({provider.errors_in_row} ошибок), пауза {cooldown}с")
    provider.errors_in_row = 0; _interruptible_sleep(cooldown)

def _calc_daily_limit_wait(exc: DailyLimitError) -> float:
    """Calculate seconds to wait until daily limit resets."""
    if exc.resume_at:
        try:
            resume = datetime.fromisoformat(exc.resume_at.replace("Z", "+00:00"))
            wait = (resume - datetime.now(timezone.utc)).total_seconds()
            if wait > 0: return min(wait + 60, 86400)
        except (ValueError, TypeError) as e:
            log_debug(f"[Worker] Ошибка парсинга resume_at: {e}")
    return 3600.0

def _extract_retry_after(err: str) -> float:
    """Extract retry_after value from error string."""
    m = re.search(r'retry_after=(\d+)', err)
    return float(m.group(1)) if m else 5.0
