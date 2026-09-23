# Local Reverse Proxy

Локальный reverse proxy на FastAPI: открывает любой сайт через `localhost`.
Полезен, когда нужен доступ к сайту из среды вроде JupyterHub, где `localhost`
доступен из браузера только через прокси-префикс вида
`https://jupyterhub/user/<login>/proxy/<port>/`.

Умеет: проксирование всех HTTP-методов и WebSocket, прозрачные cookies
(Secure и имена `__Host-`/`__Secure-` сохраняются при https-доступе через
JupyterHub; при http-доступе такие cookie переименовываются с обратной
подстановкой в запросах — иначе браузер их отбрасывает и ломается CSRF-защита
сайта, например страница «CSRF error» в HUE),
перехват редиректов, переписывание URL в HTML/JS/CSS/JSON (абсолютные,
protocol-relative, экранированные, URL-encoded и root-relative ссылки),
удаление CSP/X-Frame-Options/HSTS.

## Файлы

| Файл | Назначение |
|---|---|
| `main.py` | Сам прокси: сервер, проксирование, URL-rewriting, cookies |
| `config.py` | Загрузка настроек (config.txt + переменные окружения + дефолты) |
| `proxy_runner.py` | Запуск/остановка из Jupyter-ноутбука |
| `config.txt` | Настройки (шаблон, всё закомментировано) |
| `nginx.conf`, `docker-compose.yml` | Имитация JupyterHub для локальных тестов |
| `_csrf_lab/` | Лаборатория воспроизведения CSRF/cookie-багов: Django-стенд «псевдо-HUE» (`COOKIE_VARIANT=plain\|secure\|host`) и e2e-скрипт `flow_test.py` |

## Установка

```bash
pip install -r requirements.txt
```

## Запуск из Jupyter-ноутбука

```python
from proxy_runner import start_proxy, stop_proxy

# запуск: сайт откроется на http://localhost:8899/
server = start_proxy("https://ru.wikipedia.org", port=8899, extra_domains=[])

# остановка (повторный start_proxy тоже останавливает предыдущий инстанс)
stop_proxy()
```

Дальше сайт доступен в браузере и через httpx:

```python
import httpx

# Википедия блокирует дефолтный User-Agent python-httpx — нужен браузерный
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}

r = httpx.get("http://localhost:8899/wiki/Python",
              follow_redirects=True, timeout=30, headers=UA)
print(r.status_code, r.headers.get("content-type"), f"{len(r.content)} байт")
print("ссылок переписано на localhost:", r.text.count("localhost:8899"))
```

## Режим JupyterHub (префикс)

Если прокси доступен из браузера не напрямую, а через префикс JupyterHub,
укажите его в `config.txt`:

```
BASE_PATH=/user/my_login/proxy/8899
```

и запустите как обычно. Префикс должен совпадать с фактическим
(`/user/<логин>/proxy/<порт>` у jupyter-server-proxy). Все ссылки в HTML/JS/CSS
будут переписаны с учётом префикса.

Можно и без правки config.txt, прямо в вызове:

```python
server = start_proxy("https://ru.wikipedia.org", port=8899, extra_domains=[],
                     base_path="/user/my_login/proxy/8899")
```

## Настройки (`config.txt`)

Читаются один раз при старте процесса — после правки файла перезапустите ядро
(или передавайте параметры в `start_proxy`). Приоритет: переменные окружения >
config.txt > дефолты.

| Параметр | По умолчанию | Описание |
|---|---|---|
| `TARGET_URL` | `https://ru.wikipedia.org` | Целевой сайт |
| `EXTRA_TARGET_DOMAINS` | пусто | Доп. домены (CDN/SSO) через запятую, доступны как `/__<домен>__/...` |
| `PROXY_HOST` / `PROXY_PORT` | `127.0.0.1` / `8000` | Где слушать |
| `BASE_PATH` | пусто | Префикс JupyterHub (путь), см. выше |
| `MAX_REWRITE_BODY_SIZE` | `8388608` | Тела больше — отдаются без переписывания |
| `DEBUG` | пусто | `1` — подробные логи |

## Ограничения

- URL, которые JS строит в рантайме конкатенацией строк, не переписываются
  (для серверного HTML вроде Википедии некритично).
- Один запущенный прокси = один целевой сайт.
