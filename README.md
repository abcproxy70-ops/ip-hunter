# IP Hunter v2.1

Параллельный перебор Floating IP у **Selectel**, **Timeweb** и **Reg.ru**.
Ищет IP, попадающие в целевые подсети (MegaFon peering).

Каждый провайдер работает в отдельном потоке. Мульти-аккаунт — несколько аккаунтов параллельно.

---

## Установка

```bash
cd /opt
git clone https://github.com/abcproxy70-ops/ip-hunter.git
cd ip-hunter
pip install requests PySocks --break-system-packages
```

## Настройка

```bash
python3 -m ip_hunter --setup
```

Интерактивный wizard проведёт по настройке каждого провайдера.

## Запуск

```bash
python3 -m ip_hunter
```

## Обновление

```bash
cd /opt/ip-hunter
git pull origin main
find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null
python3 -m ip_hunter
```

---

## Провайдеры

### Selectel

**Что нужно:** username, password, account_id, project_id

**Где взять:**
1. Зайти на [my.selectel.ru](https://my.selectel.ru)
2. **Account ID** — в правом верхнем углу (номер аккаунта)
3. **Project ID** — Облачная платформа → Проект → Настройки → ID проекта
4. **Username / Password** — Управление → Сервисные пользователи → создать пользователя

**Особенности:**
- Поддерживает batch mode (несколько IP за один запрос)
- Авто-обновление Keystone-токена
- При старте автоматически чистит мусорные IP (через Neutron API)
- Регионы: `ru-1` (Москва), `ru-2` (СПб), `ru-3` (СПб-2), `ru-7` (Москва-2)

---

### Timeweb

**Что нужно:** Bearer токен

**Где взять:**
1. Зайти на [timeweb.cloud](https://timeweb.cloud)
2. Настройки → API → Создать токен
3. Скопировать токен

**Особенности:**
- Дневной лимит ~10 IP на аккаунт
- Скрипт автоматически ждёт сброса лимита

---

### Reg.ru (Cloud VPS)

**Что нужно:** cookies (SESSION_ID + JWT) и Service ID

Reg.ru использует кастомную капчу, которая не решается автоматически.
Поэтому авторизация — через cookies из браузера.

#### Как получить cookies от cloud.reg.ru

**Шаг 1.** Откройте в браузере: **https://cloud.reg.ru**

**Шаг 2.** Залогиньтесь (введите email и пароль, решите капчу если потребуется)

**Шаг 3.** Откройте DevTools:
- **Chrome/Edge:** нажмите `F12` или `Ctrl+Shift+I`
- **Firefox:** нажмите `F12`
- **Safari:** `Cmd+Option+I`

**Шаг 4.** Перейдите на вкладку **Application** (Chrome) или **Storage** (Firefox)

**Шаг 5.** В левой панели: **Cookies → https://cloud.reg.ru**

**Шаг 6.** Найдите и скопируйте значения:

| Cookie | Пример | Описание |
|--------|--------|----------|
| `SESSION_ID` | `a1b2c3d4e5f6...` | Долгоживущая сессия |
| `JWT` | `eyJhbGciOiJ...` | Короткий токен (обновляется автоматически) |

**Шаг 7.** Вставьте в формате:
```
SESSION_ID=a1b2c3d4e5f6...; JWT=eyJhbGciOiJ...
```

> **Важно:** JWT протухает через ~15 минут, но скрипт автоматически
> обновляет его через SESSION_ID (POST /refresh). Главное — SESSION_ID
> должен быть валидным.

#### Как получить Service ID

1. Залогиньтесь на **cloud.reg.ru**
2. Откройте DevTools → **Network**
3. Обновите страницу
4. Найдите любой запрос к `cloudvps-graphql-server.svc.reg.ru`
5. В заголовках запроса найдите `service-id: 12345` — это ваш Service ID

Или: URL в браузере может содержать service ID — `cloud.reg.ru/servers/12345/...`

**Особенности:**
- Создаёт минимальный сервер (c1-m1-d10-hp) → получает Floating IP → проверяет → удаляет
- Эмуляция браузера (fingerprints, Sec-Ch-Ua, human-like задержки)
- При протухании SESSION_ID — скрипт скажет обновить cookies

---

## Мульти-аккаунт

Каждый провайдер поддерживает несколько аккаунтов:

- **Selectel** — до 10 аккаунтов, каждый в отдельном потоке
- **Timeweb** — несколько Bearer-токенов
- **Reg.ru** — несколько cookie-строк + service_id

Настраивается через `--setup` → "Добавить ещё аккаунт?"

## Telegram-уведомления

Скрипт отправляет в Telegram:
- ✅ Найденный IP (совпал с подсетью)
- ❌ Мусорный IP (каждый выбитый IP)
- ⏸ Дневной лимит
- ⚡ Circuit breaker
- 🚀 Старт / 📊 Завершение

**Настройка:**
1. Создайте бота через [@BotFather](https://t.me/BotFather)
2. Получите bot token
3. Напишите боту `/start`
4. Узнайте свой ID через [@userinfobot](https://t.me/userinfobot)
5. Укажите в `--setup`

## Прокси (SOCKS5)

```
socks5://user:pass@host:port
```

Можно задать глобальный прокси или отдельный для каждого провайдера.

## Флаги

| Флаг | Описание |
|------|----------|
| `--setup` | Интерактивная настройка |
| `--reset-found` | Сбросить список найденных IP |
| `--reset-blocked` | Сбросить заблокированные аккаунты |

## Файлы конфигурации

| Файл | Описание |
|------|----------|
| `ip_hunter_config.json` | Основной конфиг (создаётся при --setup) |
| `ip_hunter_found.json` | Найденные IP (не теряются при крэше) |
| `ip_hunter_blocked.json` | Заблокированные аккаунты |
| `ip_hunter.log` | Лог-файл |

## Структура проекта

```
ip_hunter/
├── __main__.py          # Точка входа, инициализация провайдеров, запуск потоков
├── config.py            # Конфиг, interactive setup
├── logger.py            # Thread-safe цветной логгер
├── worker.py            # Основной цикл: create → check → delete, обработка ошибок
├── subnets.py           # Целевые подсети MegaFon peering
├── proxy.py             # Парсинг и проверка SOCKS/HTTP прокси
├── session.py           # Фабрика requests.Session с retry
├── telegram.py          # Отправка уведомлений
├── state.py             # Потокобезопасное состояние
├── ui.py                # Баннеры и статистика
└── providers/
    ├── base.py          # Базовый класс провайдера
    ├── selectel.py      # Selectel (Keystone, Neutron, batch create)
    ├── timeweb.py       # Timeweb (Bearer auth)
    └── regru.py         # Reg.ru (GraphQL, cookies, browser emulation)
```

## Требования

- Python 3.10+
- `requests` >= 2.28
- `PySocks` >= 1.7 (для SOCKS-прокси)

## Логика работы

1. **Старт** — инициализация провайдеров, авто-обновление токенов
2. **Очистка** — удаление мусорных IP на аккаунтах (Neutron API для Selectel)
3. **Основной цикл** — create IP → проверить подсеть → delete если мусор
4. **При 429** — прогрессивная пауза (60с → 90с → 120с → до 180с макс)
5. **При 409 (квота)** — пауза 3с
6. **При PermissionError** — отключение аккаунта
7. **Circuit breaker** — 5 ошибок подряд (не 429) → пауза 120с
8. **Найденный IP** — сохраняется, уведомление в Telegram, поиск продолжается
