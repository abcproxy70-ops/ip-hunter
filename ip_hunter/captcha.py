"""Captcha detection and solving via 2captcha API."""

import re
import time
from typing import Optional

import requests

from ip_hunter.logger import log_debug, log_err, log_info, log_warn


_HCAPTCHA_MARKERS = ("js.hcaptcha.com", 'class="h-captcha"', "hcaptcha.render")
_RECAPTCHA_MARKERS = ("google.com/recaptcha", 'class="g-recaptcha"', "grecaptcha.render")
_SITEKEY_RE = re.compile(r'data-sitekey=["\']([^"\']+)["\']')
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)

_CREATE_TASK_URL = "https://api.2captcha.com/createTask"
_GET_RESULT_URL = "https://api.2captcha.com/getTaskResult"
_POLL_INTERVAL = 5
_POLL_MAX_ATTEMPTS = 60


def detect_captcha(
    session: requests.Session, fingerprint_ua: str
) -> tuple[str, str]:
    """Detect captcha type and sitekey on reg.ru login pages.

    Args:
        session: Requests session (with cookies from reg.ru).
        fingerprint_ua: User-Agent string for the request.

    Returns:
        Tuple of (sitekey, captcha_type) where captcha_type is
        "hcaptcha" or "recaptcha". Returns ("", "") if not detected.
    """
    headers = {"User-Agent": fingerprint_ua}
    pages_html: list[str] = []

    # www.reg.ru/user/authorize — основная страница с капчей (может вернуть 403, но HTML с sitekey)
    # login.reg.ru — может быть альтернативная
    for url in (
        "https://www.reg.ru/user/authorize",
        "https://login.reg.ru/",
        "https://login.reg.ru/user/authorize",
    ):
        try:
            resp = session.get(url, headers=headers, timeout=(10, 20))
            # 403 с HTML тоже содержит sitekey (www.reg.ru/user/authorize)
            if resp.status_code in (200, 403) and len(resp.text) > 500:
                pages_html.append(resp.text)
                log_debug(f"[Captcha] {url} → {resp.status_code} ({len(resp.text)} bytes)")
            else:
                log_debug(f"[Captcha] {url} вернул {resp.status_code} ({len(resp.text)} bytes)")
        except Exception as exc:
            log_debug(f"[Captcha] Ошибка загрузки {url}: {exc}")

    combined = "\n".join(pages_html)
    if not combined:
        log_debug("[Captcha] Не удалось загрузить страницы")
        return ("", "")

    # Определяем тип капчи по маркерам
    has_hcaptcha = any(m in combined for m in _HCAPTCHA_MARKERS)
    has_recaptcha = any(m in combined for m in _RECAPTCHA_MARKERS)

    # Извлекаем sitekey
    sitekeys = _SITEKEY_RE.findall(combined)
    if not sitekeys:
        log_debug("[Captcha] data-sitekey не найден")
        return ("", "")

    for sk in sitekeys:
        sk = sk.strip()
        if _UUID_RE.match(sk):
            log_info(f"[Captcha] hCaptcha sitekey: {sk}")
            return (sk, "hcaptcha")
        if sk.startswith("6L"):
            log_info(f"[Captcha] reCAPTCHA sitekey: {sk}")
            return (sk, "recaptcha")

    # Определяем по маркерам, если формат sitekey неоднозначен
    sk = sitekeys[0].strip()
    if has_hcaptcha and not has_recaptcha:
        log_info(f"[Captcha] hCaptcha (по маркерам) sitekey: {sk}")
        return (sk, "hcaptcha")
    if has_recaptcha and not has_hcaptcha:
        log_info(f"[Captcha] reCAPTCHA (по маркерам) sitekey: {sk}")
        return (sk, "recaptcha")

    log_debug(f"[Captcha] Не удалось определить тип для sitekey: {sk}")
    return ("", "")


def solve_captcha(api_key: str, sitekey: str, captcha_type: str) -> str:
    """Solve captcha via 2captcha API.

    Args:
        api_key: 2captcha API key.
        sitekey: Captcha sitekey from detect_captcha().
        captcha_type: "hcaptcha" or "recaptcha".

    Returns:
        Captcha solution token, or empty string on failure.
    """
    if not api_key or not sitekey:
        log_err("[Captcha] Не задан api_key или sitekey")
        return ""

    # Формируем задачу
    if captcha_type == "hcaptcha":
        task = {
            "type": "HCaptchaTaskProxyless",
            "websiteURL": "https://login.reg.ru/",
            "websiteKey": sitekey,
        }
    elif captcha_type == "recaptcha":
        task = {
            "type": "RecaptchaV2TaskProxyless",
            "websiteURL": "https://login.reg.ru/user/authorize",
            "websiteKey": sitekey,
        }
    else:
        log_err(f"[Captcha] Неизвестный тип: {captcha_type}")
        return ""

    # Создаём задачу
    try:
        resp = requests.post(
            _CREATE_TASK_URL,
            json={"clientKey": api_key, "task": task},
            timeout=(10, 30),
        )
        data = resp.json()
    except Exception as exc:
        log_err(f"[Captcha] Ошибка createTask: {exc}")
        return ""

    if data.get("errorId", 0) != 0:
        log_err(f"[Captcha] createTask error: {data.get('errorDescription', '?')}")
        return ""

    task_id = data.get("taskId")
    if not task_id:
        log_err("[Captcha] Нет taskId в ответе")
        return ""

    log_info(f"[Captcha] Задача создана: {task_id}, ожидаем решение...")

    # Поллинг результата
    for attempt in range(_POLL_MAX_ATTEMPTS):
        time.sleep(_POLL_INTERVAL)
        try:
            resp = requests.post(
                _GET_RESULT_URL,
                json={"clientKey": api_key, "taskId": task_id},
                timeout=(10, 30),
            )
            result = resp.json()
        except Exception as exc:
            log_debug(f"[Captcha] Ошибка поллинга ({attempt}): {exc}")
            continue

        if result.get("errorId", 0) != 0:
            log_err(f"[Captcha] getTaskResult error: {result.get('errorDescription', '?')}")
            return ""

        status = result.get("status", "")
        if status == "processing":
            continue

        if status == "ready":
            solution = result.get("solution", {})
            # hCaptcha → solution.token, reCAPTCHA → solution.gRecaptchaResponse
            token = solution.get("token") or solution.get("gRecaptchaResponse") or ""
            if token:
                log_info(f"[Captcha] Решение получено ({len(token)} символов)")
                return token
            log_err(f"[Captcha] Пустой токен в solution: {solution}")
            return ""

        log_warn(f"[Captcha] Неожиданный статус: {status}")

    log_err(f"[Captcha] Таймаут ({_POLL_MAX_ATTEMPTS * _POLL_INTERVAL}с)")
    return ""
