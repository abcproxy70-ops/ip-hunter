# IP Hunter v2

Параллельный перебор Floating IP у Selectel, Timeweb и Reg.ru.
Ищет IP, попадающие в целевые подсети MegaFon peering.

## Быстрый старт (одна команда)

```bash
git clone https://github.com/YOUR_USER/ip-hunter.git && cd ip-hunter && pip install -r requirements.txt && python3 -m ip_hunter --setup
```

## Пошаговая установка

```bash
# 1. Клонировать
git clone https://github.com/YOUR_USER/ip-hunter.git
cd ip-hunter

# 2. (Рекомендуется) Виртуальное окружение
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 3. Установить зависимости
pip install -r requirements.txt

# 4. Настроить (интерактивный wizard)
python3 -m ip_hunter --setup
```

## Запуск

```bash
python3 -m ip_hunter
```

## Флаги

| Флаг | Описание |
|------|----------|
| `--setup` | Интерактивная настройка (токены, регионы, прокси, Telegram) |
| `--debug` | Подробный вывод в консоль |
| `--reset-found` | Сбросить список найденных IP |
| `--reset-blocked` | Сбросить заблокированные аккаунты |

## Провайдеры

| Провайдер | API | Метод |
|-----------|-----|-------|
| **Selectel** | REST (VPC Resell) | Floating IP create/delete, batch mode |
| **Timeweb** | REST (Cloud API v1) | Floating IP create/delete |
| **Reg.ru** | GraphQL (Cloud VPS) | Server create с floating IP → poll → delete |

## Конфигурация

Файл `ip_hunter_config.json` создаётся автоматически при `--setup`.
Можно редактировать вручную — новые поля из defaults подтянутся автоматически.

### Selectel
- Где взять Project ID: `my.selectel.ru` → Облачная платформа → Проект → Настройки
- Авторизация: Keystone (username + password) или API key
- Регионы: `ru-1` (Москва), `ru-2` (СПб), `ru-3` (СПб-2), `ru-7` (Москва-2)

### Timeweb
- Bearer токен из личного кабинета
- Зоны: `spb-2`, `spb-3`

### Reg.ru
- Login/password от cloud.reg.ru
- Опционально: 2captcha API key для обхода капчи

## Мульти-аккаунт

Каждый провайдер поддерживает несколько аккаунтов — настраивается через `--setup`.
RPM автоматически делится между аккаунтами на одном прокси.

## Тесты

```bash
pip install pytest
pytest tests/ -v
```

## Структура

```
ip_hunter/
├── __main__.py          # CLI entrypoint
├── config.py            # Config dataclass, save/load, interactive setup
├── logger.py            # Thread-safe colored logger
├── subnets.py           # Subnet constants + fast O(1) matching
├── rate_limiter.py      # Adaptive sliding window rate limiter
├── proxy.py             # SOCKS/HTTP proxy parsing and checking
├── session.py           # requests.Session factory with retry
├── telegram.py          # Telegram notifications
├── state.py             # Thread-safe shared state + blocked accounts
├── captcha.py           # hCaptcha/reCAPTCHA detection + 2captcha solving
├── worker.py            # Worker loop, async delete with retry
├── ui.py                # Terminal banners and stats
└── providers/
    ├── base.py          # ABC + ProviderResult dataclass
    ├── selectel.py      # Selectel (Keystone auth, batch create)
    ├── timeweb.py       # Timeweb (Bearer auth)
    └── regru.py         # Reg.ru (GraphQL, browser emulation, captcha)
```

## Требования

- Python 3.10+
- `requests` >= 2.28
- `PySocks` >= 1.7 (для SOCKS-прокси)
