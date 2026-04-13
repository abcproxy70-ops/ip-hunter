"""Core unit tests for IP Hunter."""

import io
import json
import re
import sys
import tempfile
import threading
from pathlib import Path
from threading import Thread
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from ip_hunter.subnets import fast_match, parse_subnets
from ip_hunter.rate_limiter import AdaptiveRateLimiter
from ip_hunter.state import SharedState


# ── Subnets ──


def test_fast_match_hit():
    """IP 82.202.249.100 должен попасть в 82.202.249.0/24."""
    subnets = parse_subnets("82.202.249.0/24,5.188.113.0/24")
    assert fast_match("82.202.249.100", subnets) == "82.202.249.0/24"


def test_fast_match_miss():
    """IP 1.2.3.4 не попадает ни в одну подсеть."""
    subnets = parse_subnets("82.202.249.0/24")
    assert fast_match("1.2.3.4", subnets) is None


def test_fast_match_invalid_ip():
    """Невалидный IP возвращает None."""
    subnets = parse_subnets("82.202.249.0/24")
    assert fast_match("not-an-ip", subnets) is None


def test_parse_subnets():
    """Парсинг строки с пробелами и пустыми элементами."""
    s = parse_subnets(" 10.0.0.0/24 , 192.168.1.0/24 , , ")
    assert len(s) == 2


# ── Selectel 409 handling ──


def test_selectel_409_partial_parse():
    """При 409 с IP в теле — результаты парсятся, не теряются."""
    from ip_hunter.providers.selectel import SelectelProvider

    provider = SelectelProvider.__new__(SelectelProvider)
    provider.cfg = {}
    provider.session = MagicMock()
    provider._token_mgr = None

    mock_resp = MagicMock()
    mock_resp.status_code = 409
    mock_resp.json.return_value = {
        "floatingips": [
            {"id": "x", "floating_ip_address": "1.2.3.4", "region": "ru-3"}
        ]
    }
    mock_resp.text = "conflict"

    results = provider._parse_create_response(mock_resp, "ru-3", allow_retry=False)
    assert len(results) == 1
    assert results[0].ip == "1.2.3.4"
    assert results[0].resource_id == "x"
    assert results[0].region == "ru-3"


def test_selectel_409_empty():
    """При 409 без IP — бросается RuntimeError."""
    from ip_hunter.providers.selectel import SelectelProvider

    provider = SelectelProvider.__new__(SelectelProvider)
    provider.cfg = {}
    provider.session = MagicMock()
    provider._token_mgr = None

    mock_resp = MagicMock()
    mock_resp.status_code = 409
    mock_resp.json.return_value = {"error": "quota"}
    mock_resp.text = "quota"

    with pytest.raises(RuntimeError, match="409"):
        provider._parse_create_response(mock_resp, "ru-3", allow_retry=False)


# ── Rate Limiter ──


def test_rate_limiter_on_429():
    """on_rate_limit снижает RPM до max(4, int(rpm*0.7))."""
    rl = AdaptiveRateLimiter(rpm_max=20)
    assert rl.current_rpm == 20
    rl.on_rate_limit()
    assert rl.current_rpm == 14  # max(4, int(20*0.7))


def test_rate_limiter_recovery():
    """После 20 успехов RPM увеличивается на 1."""
    rl = AdaptiveRateLimiter(rpm_max=20)
    rl.on_rate_limit()  # → 14
    assert rl.current_rpm == 14
    for _ in range(20):
        rl.on_success()
    assert rl.current_rpm == 15  # 14 + 1


# ── Config ──


def test_config_deep_merge():
    """Config.load() подтягивает новые поля из defaults."""
    from ip_hunter.config import Config, CONFIG_FILE

    # Сохраняем минимальный JSON без circuit_breaker_threshold
    partial = {"rpm_limit": 42, "selectel": {"enabled": True}}
    tmp = CONFIG_FILE
    original_exists = tmp.exists()
    original_content = tmp.read_text(encoding="utf-8") if original_exists else None

    try:
        tmp.write_text(json.dumps(partial), encoding="utf-8")
        cfg = Config.load()
        assert cfg.rpm_limit == 42
        assert cfg.circuit_breaker_threshold == 5  # default
        assert cfg.selectel["enabled"] is True
    finally:
        if original_content is not None:
            tmp.write_text(original_content, encoding="utf-8")
        elif tmp.exists():
            tmp.unlink()


# ── Captcha detection ──


def test_captcha_type_detection_hcaptcha():
    """hCaptcha sitekey в UUID-формате определяется как hcaptcha."""
    import re
    from ip_hunter.captcha import _SITEKEY_RE, _UUID_RE

    html = (
        '<script src="https://js.hcaptcha.com/1/api.js"></script>'
        '<div class="h-captcha" data-sitekey="a5f74b19-9e45-40e0-b45d-47ff91b7a6c2"></div>'
    )
    sitekeys = _SITEKEY_RE.findall(html)
    assert len(sitekeys) == 1
    sk = sitekeys[0]
    assert _UUID_RE.match(sk)
    assert sk == "a5f74b19-9e45-40e0-b45d-47ff91b7a6c2"


def test_captcha_type_detection_recaptcha():
    """reCAPTCHA sitekey с префиксом 6L определяется как recaptcha."""
    from ip_hunter.captcha import _SITEKEY_RE

    html = (
        '<script src="https://www.google.com/recaptcha/api.js"></script>'
        '<div class="g-recaptcha" data-sitekey="6LcXxx"></div>'
    )
    sitekeys = _SITEKEY_RE.findall(html)
    assert len(sitekeys) == 1
    assert sitekeys[0].startswith("6L")


# ── SharedState thread safety ──


def test_shared_state_thread_safety():
    """100 потоков инкрементируют global_attempt без потерь."""
    state = SharedState()
    threads = [Thread(target=lambda: state.inc_attempt("test")) for _ in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert state.global_attempt == 100
    assert state.by_provider["test"]["attempts"] == 100


# ── Proxy ──


def test_parse_proxy_socks5():
    """Парсинг socks5://user:pass@host:port."""
    from ip_hunter.proxy import parse_proxy
    result = parse_proxy("socks5://admin:secret@1.2.3.4:1080")
    assert result is not None
    assert result["scheme"] == "socks5"
    assert result["host"] == "1.2.3.4"
    assert result["port"] == "1080"
    assert result["user"] == "admin"
    assert result["password"] == "secret"


def test_parse_proxy_host_port():
    """Парсинг bare host:port → http."""
    from ip_hunter.proxy import parse_proxy
    result = parse_proxy("10.0.0.1:8080")
    assert result is not None
    assert result["scheme"] == "http"
    assert result["host"] == "10.0.0.1"
    assert result["port"] == "8080"


def test_parse_proxy_empty():
    """Пустая строка → None."""
    from ip_hunter.proxy import parse_proxy
    assert parse_proxy("") is None
    assert parse_proxy("   ") is None


def test_parse_proxy_invalid():
    """Невалидная строка → None."""
    from ip_hunter.proxy import parse_proxy
    assert parse_proxy("not-a-proxy") is None


# ── Session ──


def test_make_session_bearer():
    """Authorization header = Bearer token."""
    from ip_hunter.session import make_session
    s = make_session("mytoken123", "Authorization")
    assert s.headers["Authorization"] == "Bearer mytoken123"
    assert s.headers["Content-Type"] == "application/json"
    s.close()


def test_make_session_custom_header():
    """Custom header = raw token."""
    from ip_hunter.session import make_session
    s = make_session("raw-token", "X-Auth-Token")
    assert s.headers["X-Auth-Token"] == "raw-token"
    s.close()


# ── Logger ──


def test_logger_ansi_strip_in_file():
    """Лог-файл не содержит ANSI escape кодов."""
    from ip_hunter.logger import _ANSI_RE
    colored = "\033[32m[✓]\033[0m Тест пройден"
    clean = _ANSI_RE.sub("", colored)
    assert "\033[" not in clean
    assert "[✓] Тест пройден" == clean


def test_logger_timestamp_format():
    """Таймстамп в формате HH:MM:SS."""
    from ip_hunter.logger import _timestamp
    ts = _timestamp()
    assert re.match(r"^\d{2}:\d{2}:\d{2}$", ts)


# ── UI ──


def test_format_duration():
    """Форматирование длительности."""
    from ip_hunter.ui import _format_duration
    assert _format_duration(45) == "45с"
    assert _format_duration(90) == "1м 30с"
    assert _format_duration(3661) == "1ч 1м 1с"


# ── Worker integration (mocked) ──


def test_process_result_match():
    """_process_result возвращает True при совпадении с подсетью."""
    from ip_hunter.worker import _process_result
    from ip_hunter.providers.base import ProviderResult

    subnets = parse_subnets("82.202.249.0/24")
    result = ProviderResult(ip="82.202.249.55", resource_id="r1", region="ru-2")
    state = SharedState()
    provider = MagicMock()
    provider.name = "selectel"
    cfg = {"telegram_bot_token": "", "telegram_admin_id": ""}

    matched = _process_result(result, subnets, provider, cfg, state,
                               "ru-2", 1, "[TEST]", "selectel:test", "test")
    assert matched is True
    assert state.total_found == 1
    assert state.found_ips[0]["ip"] == "82.202.249.55"


def test_process_result_miss():
    """_process_result возвращает False при промахе."""
    from ip_hunter.worker import _process_result
    from ip_hunter.providers.base import ProviderResult

    subnets = parse_subnets("82.202.249.0/24")
    result = ProviderResult(ip="1.2.3.4", resource_id="r2", region="ru-3")
    state = SharedState()
    provider = MagicMock()
    provider.name = "timeweb"
    cfg = {"telegram_bot_token": "", "telegram_admin_id": ""}

    matched = _process_result(result, subnets, provider, cfg, state,
                               "ru-3", 1, "[TEST]", "timeweb:test", "test")
    assert matched is False
    assert state.total_found == 0


def test_worker_create_delete_cycle():
    """Полный цикл: create → miss → async delete через _do_single."""
    from ip_hunter.worker import _do_single
    from ip_hunter.providers.base import ProviderResult
    import ip_hunter.worker as worker_mod

    subnets = parse_subnets("10.0.0.0/24")
    state = SharedState()
    provider = MagicMock()
    provider.name = "timeweb"
    provider.create_ip.return_value = ProviderResult(
        ip="5.5.5.5", resource_id="rid-1", region="spb-2"
    )
    cfg = {"telegram_bot_token": "", "telegram_admin_id": ""}
    region_hits = {"spb-2": 0}

    with patch.object(worker_mod, '_delete_async') as mock_da:
        _do_single(provider, subnets, cfg, state, "spb-2", 1,
                   "[TEST]", "timeweb:test", "test", region_hits)
        mock_da.assert_called_once_with(provider, "rid-1", state, "timeweb:test")
    provider.create_ip.assert_called_once_with("spb-2")
    assert state.total_found == 0


def test_worker_create_match_no_delete():
    """При совпадении — IP не удаляется."""
    from ip_hunter.worker import _do_single
    from ip_hunter.providers.base import ProviderResult
    import ip_hunter.worker as worker_mod

    subnets = parse_subnets("5.5.5.0/24")
    state = SharedState()
    provider = MagicMock()
    provider.name = "timeweb"
    provider.create_ip.return_value = ProviderResult(
        ip="5.5.5.5", resource_id="rid-2", region="spb-2"
    )
    cfg = {"telegram_bot_token": "", "telegram_admin_id": ""}
    region_hits = {"spb-2": 0}

    with patch.object(worker_mod, '_delete_async') as mock_da:
        _do_single(provider, subnets, cfg, state, "spb-2", 1,
                   "[TEST]", "timeweb:test", "test", region_hits)
        mock_da.assert_not_called()
    assert state.total_found == 1
    assert region_hits["spb-2"] == 1


def test_backoff_delay():
    """backoff_delay возвращает значение в ожидаемом диапазоне."""
    from ip_hunter.worker import backoff_delay
    # errors=0 → base * 2^0 = 2.0, ±30% jitter → [1.4, 2.6]
    for _ in range(20):
        d = backoff_delay(0, base=2.0, cap=60.0)
        assert 1.4 <= d <= 2.6
    # errors=10 → capped at 60, ±30% → [42, 78]
    for _ in range(20):
        d = backoff_delay(10, base=2.0, cap=60.0)
        assert 42.0 <= d <= 78.0


def test_selectel_create_ip_returns_single():
    """Selectel create_ip возвращает ProviderResult, не list."""
    from ip_hunter.providers.selectel import SelectelProvider
    from ip_hunter.providers.base import ProviderResult

    provider = SelectelProvider.__new__(SelectelProvider)
    provider.cfg = {}
    provider._base = "https://api.selectel.ru/vpc/resell"
    provider._project_id = "test"
    provider.timeout = (10, 30)
    provider.session = MagicMock()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "floatingips": [{"id": "abc", "floating_ip_address": "1.2.3.4", "region": "ru-2"}]
    }
    provider.session.post.return_value = mock_resp

    result = provider.create_ip("ru-2")
    assert isinstance(result, ProviderResult)
    assert result.ip == "1.2.3.4"
    assert result.resource_id == "abc"


# ── Timeweb ──


def test_timeweb_403_daily_limit():
    """403 + daily_limit_exceeded → DailyLimitError с resume_at."""
    from ip_hunter.providers.timeweb import TimewebProvider
    from ip_hunter.providers.base import DailyLimitError

    provider = TimewebProvider.__new__(TimewebProvider)
    provider.cfg = {}
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.json.return_value = {
        "error_code": "daily_limit_exceeded",
        "message": "limit",
        "details": {"available_date_for_creation": "2025-01-01T00:00:00Z"},
    }
    mock_resp.text = "limit"
    with pytest.raises(DailyLimitError) as exc_info:
        provider._handle_403(mock_resp)
    assert exc_info.value.resume_at == "2025-01-01T00:00:00Z"


def test_timeweb_403_no_balance():
    """403 + no_balance_for_month → DailyLimitError (временная, не блокировка)."""
    from ip_hunter.providers.timeweb import TimewebProvider
    from ip_hunter.providers.base import DailyLimitError

    provider = TimewebProvider.__new__(TimewebProvider)
    provider.cfg = {}
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.json.return_value = {
        "error_code": "no_balance_for_month",
        "message": "no money",
    }
    mock_resp.text = "no money"
    with pytest.raises(DailyLimitError):
        provider._handle_403(mock_resp)


def test_timeweb_403_unknown():
    """403 + неизвестный error_code → RuntimeError."""
    from ip_hunter.providers.timeweb import TimewebProvider

    provider = TimewebProvider.__new__(TimewebProvider)
    provider.cfg = {}
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.json.return_value = {
        "error_code": "something_else",
        "message": "unknown",
    }
    mock_resp.text = "unknown"
    with pytest.raises(RuntimeError, match="403"):
        provider._handle_403(mock_resp)


# ── Telegram ──


def test_send_telegram_empty_token():
    """Пустой токен или admin_id → ничего не отправляется, нет исключений."""
    from ip_hunter.telegram import send_telegram

    send_telegram("", "123", "test")  # пустой token
    send_telegram("tok", "", "test")  # пустой admin_id


# ── Regru ──


def test_regru_jwt_decode_valid():
    """JWT exp декодируется корректно."""
    from ip_hunter.providers.regru import _decode_jwt_exp
    import base64 as b64

    payload = b64.urlsafe_b64encode(
        json.dumps({"exp": 1700000000}).encode()
    ).rstrip(b"=").decode()
    jwt_str = f"header.{payload}.signature"
    assert _decode_jwt_exp(jwt_str) == 1700000000.0


def test_regru_jwt_decode_invalid():
    """Невалидный JWT → 0.0."""
    from ip_hunter.providers.regru import _decode_jwt_exp

    assert _decode_jwt_exp("invalid") == 0.0
    assert _decode_jwt_exp("") == 0.0
    assert _decode_jwt_exp("a.b") == 0.0


def test_regru_random_server_name():
    """Имя сервера в формате 'Adj Noun NNN'."""
    from ip_hunter.providers.regru import _random_server_name

    for _ in range(20):
        name = _random_server_name()
        parts = name.split()
        assert len(parts) == 3
        assert parts[2].isdigit()
        assert 100 <= int(parts[2]) <= 999


def test_regru_schema_cache_class_level():
    """Schema cache живёт на классе, а не в глобалах."""
    from ip_hunter.providers.regru import RegruProvider

    assert hasattr(RegruProvider, "_schema_list_field")
    assert hasattr(RegruProvider, "_schema_meta_field")
    # Убеждаемся что это class attrs, не instance
    assert "_schema_list_field" in RegruProvider.__dict__


# ── State deduplication ──


def test_state_add_found_dedup():
    """Повторный IP не добавляется."""
    state = SharedState()
    first = state.add_found("1.2.3.4", "test", "ru-1", "1.2.3.0/24", "r1", "t1")
    second = state.add_found("1.2.3.4", "test", "ru-1", "1.2.3.0/24", "r1", "t1")
    assert first is True
    assert second is False
    assert state.total_found == 1


# ── Config deep merge nested ──


def test_config_deep_merge_nested():
    """Deep merge сохраняет новые вложенные ключи из defaults."""
    from ip_hunter.config import Config

    base = {"a": {"x": 1, "y": 2}, "b": 3}
    override = {"a": {"x": 10}}
    merged = Config._deep_merge(base, override)
    assert merged == {"a": {"x": 10, "y": 2}, "b": 3}


# ── Selectel delete chain ──


def test_selectel_401_retry_on_create():
    """При 401 _do_create обновляет токен и повторяет запрос."""
    from ip_hunter.providers.selectel import SelectelProvider

    provider = SelectelProvider.__new__(SelectelProvider)
    provider.cfg = {}
    provider._base = "https://api.selectel.ru/vpc/resell"
    provider._project_id = "test"
    provider.timeout = (10, 30)
    provider.session = MagicMock()
    provider._token_mgr = MagicMock()
    provider._token_mgr.get_token.return_value = "new-token"

    # Первый запрос → 401, второй → 200 с IP
    resp_401 = MagicMock()
    resp_401.status_code = 401
    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {
        "floatingips": [{"id": "abc", "floating_ip_address": "1.2.3.4", "region": "ru-2"}]
    }
    provider.session.post.side_effect = [resp_401, resp_200]

    result = provider.create_ip("ru-2")
    assert result.ip == "1.2.3.4"
    assert provider.session.post.call_count == 2
    provider._token_mgr.get_token.assert_called_once_with(force_refresh=True)


def test_delete_async_passes_provider_name_and_retries():
    """_delete_async передаёт имя провайдера и делает retry."""
    from ip_hunter.worker import _delete_async
    import time as _time

    provider = MagicMock()
    provider.name = "selectel"
    provider.delete_ip.side_effect = [RuntimeError("(429)"), None]

    state = SharedState()
    _delete_async(provider, "test-rid", state, thread_label="selectel:test", max_retries=2)
    _time.sleep(3.5)  # retry sleep = 2с + margin
    assert provider.delete_ip.call_count == 2
    assert state.total_deleted == 1


def test_selectel_single_create_no_ip_leak():
    """create_ip с quantity=1 при 409 partial — макс 1 IP, утечки нет."""
    from ip_hunter.providers.selectel import SelectelProvider
    from ip_hunter.providers.base import ProviderResult

    provider = SelectelProvider.__new__(SelectelProvider)
    provider.cfg = {}
    provider._base = "https://api.selectel.ru/vpc/resell"
    provider._project_id = "test"
    provider.timeout = (10, 30)
    provider.session = MagicMock()
    provider._token_mgr = None

    # 409 с одним IP в partial
    mock_resp = MagicMock()
    mock_resp.status_code = 409
    mock_resp.json.return_value = {
        "floatingips": [{"id": "leaked", "floating_ip_address": "5.6.7.8", "region": "ru-3"}]
    }
    mock_resp.text = "conflict"
    provider.session.post.return_value = mock_resp

    result = provider.create_ip("ru-3")
    # IP возвращён caller'у, а не потерян
    assert isinstance(result, ProviderResult)
    assert result.ip == "5.6.7.8"
    assert result.resource_id == "leaked"


def test_selectel_batch_delete_non_matching():
    """Batch create: не-matching IP удаляются через _delete_async."""
    from ip_hunter.worker import _do_selectel_batch
    from ip_hunter.providers.base import ProviderResult
    import ip_hunter.worker as worker_mod

    subnets = parse_subnets("10.0.0.0/24")
    state = SharedState()
    provider = MagicMock()
    provider.name = "selectel"
    provider.create_ip_multi_region.return_value = [
        ProviderResult(ip="5.5.5.1", resource_id="r1", region="ru-2"),
        ProviderResult(ip="5.5.5.2", resource_id="r2", region="ru-3"),
    ]
    cfg = {"telegram_bot_token": "", "telegram_admin_id": ""}
    region_hits = {"ru-2": 0, "ru-3": 0}

    with patch.object(worker_mod, '_delete_async') as mock_da:
        _do_selectel_batch(provider, subnets, cfg, state, ["ru-2", "ru-3"],
                           1, 1, "[TEST]", "sel:t", "t", region_hits)
        assert mock_da.call_count == 2
        deleted_rids = {call.args[1] for call in mock_da.call_args_list}
        assert deleted_rids == {"r1", "r2"}
        # Проверяем что thread_label передаётся
        for call in mock_da.call_args_list:
            assert call.args[3] == "sel:t"

