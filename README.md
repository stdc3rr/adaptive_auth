# Adaptive Authentication Prototype (Django + DRF + PostgreSQL)

Учебный прототип адаптивной аутентификации с rule-based оценкой риска и базовой защитой от атак социальной инженерии.

## Что реализовано

- Регистрация пользователя.
- Вход по логину/email и паролю.
- Адаптивная аутентификация на сервере.
- Расчет риск-скоринга по 4 группам факторов.
- Реакция по 3 уровням риска: `allow` / `require_mfa` / `block`.
- Дополнительная проверка MFA (одноразовый код).
- Ограничение перебора пароля (soft lock).
- Журнал событий безопасности.
- Базовые уведомления пользователю о подозрительных входах.
- Интерфейс: вход, регистрация, результат, профиль, история входов.

## Структура модулей

- `users` - профиль доверенного поведения и доверенные устройства.
- `authentication` - API регистрации/входа/MFA, попытки входа, throttling.
- `risk` - центральная логика формул и риск-скоринга (`risk/services/scoring.py`).
- `security_log` - журнал событий безопасности.
- `notifications` - базовые уведомления (DB-записи).
- `frontend` - HTML-страницы и маршруты интерфейса.

## Где используются формулы

Файл: `risk/services/scoring.py`, функция `score_login_attempt`.

1. Пространственно-временной риск:

`X_gt = alpha * x_geo + (1 - alpha) * x_time`

2. Риск устройства и браузерной среды:

`X_dev = 1 - S_fp`

3. Сетевой риск:

`X_net = g_ip*x_ip + g_provider*x_prov + g_vpn*x_vpn + g_reputation*x_rep`

4. Поведенческий риск:

`X_sess = d_tries*x_tries + d_speed*x_speed + d_delay*x_delay + d_repeat*x_repeat`

5. Интегральная оценка:

`R_ctx = w_gt*X_gt + w_dev*X_dev + w_net*X_net + w_sess*X_sess`

### Интерпретация score

- `0.00 - RISK_LOW_MAX`: низкий риск, решение `allow`.
- `RISK_LOW_MAX - RISK_MEDIUM_MAX`: средний риск, `require_mfa`.
- `> RISK_MEDIUM_MAX`: высокий риск, `block`.

Пороги и веса вынесены в:

- `config/constants.py`
- `settings.ADAPTIVE_AUTH` в `config/settings.py`

## Установка и запуск с нуля

1. Установите PostgreSQL и создайте БД:

```sql
CREATE DATABASE adaptive_auth;
```

2. Перейдите в папку проекта:

```bash
cd adaptive_auth
```

3. Создайте виртуальное окружение и активируйте его.

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

4. Установите зависимости:

```bash
pip install -r requirements.txt
```

5. Подготовьте `.env`:

- Скопируйте `.env.example` в `.env`.
- Заполните параметры подключения к PostgreSQL.

6. Выполните миграции:

```bash
python manage.py makemigrations
python manage.py migrate
```

7. Создайте superuser (опционально):

```bash
python manage.py createsuperuser
```

8. Запустите сервер:

```bash
python manage.py runserver
```

9. Откройте:

- `http://127.0.0.1:8000/` - вход
- `http://127.0.0.1:8000/register/` - регистрация
- `http://127.0.0.1:8000/profile/` - профиль
- `http://127.0.0.1:8000/history/` - история

## Безопасность и ограничения прототипа

- Пароли хранятся безопасно через встроенные механизмы Django.
- MFA реализована как учебный одноразовый код.
- В `DEBUG=True` MFA-код возвращается в API-ответе для локальной демонстрации.
- Реализован soft lock при множестве неудачных попыток.
- Ошибки логина не раскрывают внутреннюю логику скоринга.
- Проект не использует ML и внешние риск-сервисы, только прозрачные правила.

## API (кратко)

- `POST /api/auth/register/`
- `POST /api/auth/login/`
- `POST /api/auth/verify-mfa/`
- `GET /api/auth/attempt/<attempt_id>/`

## Демонстрация защиты от социальной инженерии

Даже при верном пароле вход может быть ограничен, если контекст нетипичен:

- новый город/часовой пояс,
- незнакомый fingerprint,
- подозрительная сеть/VPN,
- аномально быстрые или повторные попытки.

Таким образом, знание пароля само по себе не гарантирует доступ.
