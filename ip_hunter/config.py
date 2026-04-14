"""Configuration management for IP Hunter."""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ip_hunter.logger import log_debug, log_info

CONFIG_FILE = Path.cwd() / "ip_hunter_config.json"
FOUND_IPS_FILE = Path.cwd() / "ip_hunter_found.json"
BLOCKED_FILE = Path.cwd() / "ip_hunter_blocked.json"


@dataclass
class Config:
    """Main configuration container for IP Hunter."""

    selectel: dict = field(default_factory=lambda: {
        "enabled": False, "token": "", "extra": {
            "project_id": "", "regions": ["ru-2", "ru-3"],
            "api_base": "https://api.selectel.ru/vpc/resell/",
            "account_id": "", "username": "", "password": "",
            "api_key": "", "project_name": "",
            "extra_accounts": [], "batch_size": 2,
        }
    })
    timeweb: dict = field(default_factory=lambda: {
        "enabled": False, "token": "", "extra": {
            "availability_zones": ["spb-2", "spb-3"],
            "extra_tokens": [],
        }
    })
    regru: dict = field(default_factory=lambda: {
        "enabled": False, "token": "", "extra": {
            "service_id": "", "region": "openstack-msk1",
            "image": "ubuntu-24-04-amd64", "plan": "c2-m2-d20-hp",
            "login": "", "password": "", "extra_accounts": [],
        }
    })
    custom_subnets: dict = field(default_factory=lambda: {
        "selectel": "", "timeweb": "", "regru": ""
    })
    attempts_per_provider: int = 150
    rpm_limit: int = 60
    connect_timeout: int = 10
    request_timeout: int = 30
    circuit_breaker_threshold: int = 5
    circuit_breaker_cooldown: int = 120
    proxy: str = ""
    proxy_selectel: str = ""
    proxy_timeweb: str = ""
    proxy_regru: str = ""
    telegram_bot_token: str = ""
    telegram_admin_id: str = ""
    captcha_api_key: str = ""
    log_file: str = "ip_hunter.log"

    @property
    def timeouts(self) -> tuple[int, int]:
        """Return (connect_timeout, request_timeout) tuple."""
        return (self.connect_timeout, self.request_timeout)

    def save(self) -> None:
        """Save config to JSON file."""
        data = self._to_dict()
        try:
            CONFIG_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            log_info(f"[Config] Сохранён: {CONFIG_FILE}")
        except OSError as exc:
            log_debug(f"[Config] Ошибка сохранения: {exc}")

    def _to_dict(self) -> dict:
        """Convert config to plain dict."""
        return {
            "selectel": self.selectel, "timeweb": self.timeweb, "regru": self.regru,
            "custom_subnets": self.custom_subnets,
            "attempts_per_provider": self.attempts_per_provider,
            "rpm_limit": self.rpm_limit,
            "connect_timeout": self.connect_timeout,
            "request_timeout": self.request_timeout,
            "circuit_breaker_threshold": self.circuit_breaker_threshold,
            "circuit_breaker_cooldown": self.circuit_breaker_cooldown,
            "proxy": self.proxy,
            "proxy_selectel": self.proxy_selectel,
            "proxy_timeweb": self.proxy_timeweb,
            "proxy_regru": self.proxy_regru,
            "telegram_bot_token": self.telegram_bot_token,
            "telegram_admin_id": self.telegram_admin_id,
            "captcha_api_key": self.captcha_api_key,
            "log_file": self.log_file,
        }

    @classmethod
    def load(cls) -> "Config":
        """Load config from JSON with deep merge of defaults."""
        defaults = cls()._to_dict()
        if not CONFIG_FILE.exists():
            log_info("[Config] Файл не найден, используем defaults")
            return cls()
        try:
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log_debug(f"[Config] Ошибка чтения: {exc}")
            return cls()
        merged = cls._deep_merge(defaults, raw)
        cfg = cls()
        for k, v in merged.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Recursively merge override into base, preserving new default keys."""
        result = base.copy()
        for key, val in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(val, dict):
                result[key] = Config._deep_merge(result[key], val)
            else:
                result[key] = val
        return result


def _ask(prompt: str, default: str = "") -> str:
    """Prompt user with optional default."""
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"  {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return val if val else default


def _ask_bool(prompt: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    val = _ask(f"{prompt} ({d})", "").lower()
    if not val:
        return default
    return val in ("y", "yes", "да", "1")


def interactive_setup(cfg: Config) -> Config:
    """Interactive configuration wizard."""
    print("\n╔══════════════════════════════════════╗")
    print("║   IP Hunter — Настройка конфигурации  ║")
    print("╚══════════════════════════════════════╝\n")

    # --- Selectel ---
    if _ask_bool("Включить Selectel?", cfg.selectel.get("enabled", False)):
        cfg.selectel["enabled"] = True
        ext = cfg.selectel.setdefault("extra", {})
        print("\n  📋 Где взять Project ID: my.selectel.ru → Облачная платформа → Проект → Настройки")
        ext["project_id"] = _ask("Project ID", ext.get("project_id", ""))
        ext["account_id"] = _ask("Account ID (номер договора)", ext.get("account_id", ""))
        print("\n  Авторизация: Keystone (username+password) ИЛИ API key")
        ext["username"] = _ask("Service user name (пусто если API key)", ext.get("username", ""))
        if ext["username"]:
            ext["password"] = _ask("Service user password", ext.get("password", ""))
            ext["project_name"] = _ask("Project name (пусто=domain scope)", ext.get("project_name", ""))
        else:
            ext["api_key"] = _ask("API key", ext.get("api_key", ""))
        if not ext["username"] and not ext["api_key"]:
            cfg.selectel["token"] = _ask("Static token (fallback)", cfg.selectel.get("token", ""))
        print("  Регионы: ru-1 (Москва), ru-2 (СПб), ru-3 (СПб-2), ru-7 (Москва-2)")
        r = _ask("Регионы через запятую", ",".join(ext.get("regions", ["ru-2", "ru-3"])))
        ext["regions"] = [x.strip() for x in r.split(",") if x.strip()]
        ext["batch_size"] = int(_ask("Batch size", str(ext.get("batch_size", 2))))
        # Extra accounts
        ext["extra_accounts"] = ext.get("extra_accounts", [])
        while _ask_bool("Добавить ещё аккаунт Selectel?", False):
            acc = {"account_id": _ask("Account ID"), "username": _ask("Username"),
                   "password": _ask("Password"), "project_id": _ask("Project ID"),
                   "project_name": _ask("Project name (пусто=domain)", "")}
            ext["extra_accounts"].append(acc)
    else:
        cfg.selectel["enabled"] = False

    # --- Timeweb ---
    if _ask_bool("\nВключить Timeweb?", cfg.timeweb.get("enabled", False)):
        cfg.timeweb["enabled"] = True
        cfg.timeweb["token"] = _ask("Bearer токен", cfg.timeweb.get("token", ""))
        ext = cfg.timeweb.setdefault("extra", {})
        z = _ask("Зоны через запятую", ",".join(ext.get("availability_zones", ["spb-2", "spb-3"])))
        ext["availability_zones"] = [x.strip() for x in z.split(",") if x.strip()]
        ext["extra_tokens"] = ext.get("extra_tokens", [])
        while _ask_bool("Добавить ещё токен Timeweb?", False):
            ext["extra_tokens"].append(_ask("Bearer токен"))
    else:
        cfg.timeweb["enabled"] = False

    # --- Reg.ru ---
    if _ask_bool("\nВключить Reg.ru?", cfg.regru.get("enabled", False)):
        cfg.regru["enabled"] = True
        ext = cfg.regru.setdefault("extra", {})
        print("\n  Авторизация через cookies (SESSION_ID + JWT):")
        print("  1. Залогиньтесь на cloud.reg.ru в браузере")
        print("  2. DevTools (F12) → Application → Cookies → cloud.reg.ru")
        print("  3. Скопируйте: SESSION_ID=...; JWT=...")
        print("  (JWT протухает, но обновится автоматически через SESSION_ID)\n")
        cfg.regru["token"] = _ask("Cookies (SESSION_ID=...; JWT=...)", cfg.regru.get("token", ""))
        ext["service_id"] = _ask("Service ID (cloud VPS)", ext.get("service_id", ""))
        ext["region"] = _ask("Region", ext.get("region", "openstack-msk1"))
        ext["image"] = _ask("Image", ext.get("image", "ubuntu-24-04-amd64"))
        ext["plan"] = _ask("Plan", ext.get("plan", "c1-m1-d10-hp"))
        ext["extra_accounts"] = ext.get("extra_accounts", [])
        while _ask_bool("Добавить ещё аккаунт Reg.ru?", False):
            acc = {"token": _ask("Cookies (SESSION_ID=...; JWT=...)"),
                   "service_id": _ask("Service ID")}
            ext["extra_accounts"].append(acc)
    else:
        cfg.regru["enabled"] = False

    # --- Общие ---
    print("\n── Общие настройки ──")
    cfg.proxy = _ask("Глобальный прокси (socks5://...)", cfg.proxy)
    cfg.proxy_selectel = _ask("Прокси для Selectel (пусто=глобальный)", cfg.proxy_selectel)
    cfg.proxy_timeweb = _ask("Прокси для Timeweb (пусто=глобальный)", cfg.proxy_timeweb)
    cfg.proxy_regru = _ask("Прокси для Reg.ru (пусто=глобальный)", cfg.proxy_regru)
    cfg.telegram_bot_token = _ask("Telegram Bot Token", cfg.telegram_bot_token)
    cfg.telegram_admin_id = _ask("Telegram Admin Chat ID", cfg.telegram_admin_id)
    cfg.captcha_api_key = _ask("2captcha API Key", cfg.captcha_api_key)
    cfg.rpm_limit = int(_ask("RPM лимит", str(cfg.rpm_limit)))
    cfg.attempts_per_provider = int(_ask("Попыток на провайдер", str(cfg.attempts_per_provider)))
    cfg.log_file = _ask("Лог-файл", cfg.log_file)

    cfg.save()
    print("\n✓ Конфигурация сохранена!\n")
    return cfg
