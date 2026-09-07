#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Локальный reverse proxy: ретранслирует реальный сайт (напр. Wikipedia) на localhost.

Что умеет:
  * Catch-all HTTP-проксирование всех методов и путей (FastAPI + httpx)
  * Прозрачные cookies (переписывание Domain/Secure/SameSite + namespace по доменам)
  * Перехват редиректов 3xx с переписыванием Location (follow_redirects=False)
  * URL rewriting в HTML/JS/CSS/JSON/SSE: https://, http://, //, wss://, ws://,
    экранированные (https:\\/\\/site) и URL-encoded (https%3A%2F%2Fsite) варианты,
    «голый» домен, а также root-relative ссылки (/wiki/X, fetch("/api/...")) в
    HTML-атрибутах, CSS url(), JS-вызовах и JSON-объектах
  * Работа под префиксом JupyterHub (BASE_PATH): uvicorn получает root_path,
    а все ссылки переписываются с учётом базового пути
  * Удаление CSP / X-Frame-Options / HSTS и прочих блокирующих заголовков
  * Двусторонний WebSocket-прокси (текст + бинарные фреймы, subprotocols)
  * Дополнительные домены (CDN/SSO) через path-префикс /__<домен>__/<путь>

Запуск:
    uvicorn main:app --port 8000
    python main.py                      # эквивалентно

Конфигурация — файл config.txt / переменные окружения (см. config.py):
    TARGET_URL=     # основной целевой сайт (по умолчанию https://ru.wikipedia.org)
    EXTRA_TARGET_DOMAINS=a.com,b.com    # доп. домены (CDN/SSO), можно пустой строкой
    BASE_PATH=/user/my_login/proxy/8000 # префикс JupyterHub (пусто = обычный localhost)
    DEBUG=1                             # подробные логи
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from functools import lru_cache
from urllib.parse import quote, urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import Response, StreamingResponse
from websockets.exceptions import ConnectionClosed

# ---------------------------------------------------------------------------
# Конфигурация (config.py читает config.txt и переменные окружения)
# ---------------------------------------------------------------------------

from config import (  # noqa: E402
    BASE_PATH,
    DEBUG,
    EXTRA_TARGET_DOMAINS,
    MAX_REWRITE_BODY_SIZE,
    PROXY_HOST,
    PROXY_PORT,
    TARGET_URL,
    normalize_base_path,
)

_parsed_target = urlparse(TARGET_URL)
TARGET_DOMAIN = _parsed_target.netloc  # host[:port] основного домена
TARGET_SCHEME = _parsed_target.scheme or "https"

ALL_DOMAINS = [TARGET_DOMAIN, *EXTRA_TARGET_DOMAINS]
_EXTRA_SET = set(EXTRA_TARGET_DOMAINS)

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
)
logger = logging.getLogger("reverse-proxy")

# ---------------------------------------------------------------------------
# Совместимость версий библиотеки websockets (новый API появился в 13.0)
# ---------------------------------------------------------------------------

try:  # websockets >= 13 — новый asyncio API
    from websockets.asyncio.client import connect as _ws_connect

    _NEW_WS_API = True
except ImportError:  # старые версии — legacy API
    from websockets import connect as _ws_connect  # type: ignore[assignment]

    _NEW_WS_API = False

# ---------------------------------------------------------------------------
# Заголовки
# ---------------------------------------------------------------------------

# Hop-by-hop заголовки — терминируются на прокси (RFC 2616, 13.5.1)
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

# Что не forwarding'им в запросе к целевому сайту
STRIP_REQUEST_HEADERS = HOP_BY_HOP | {
    "host",  # httpx выставит сам (иначе цель увидит "localhost:8000")
    "content-length",  # httpx пересчитает по фактическому телу
    "accept-encoding",  # принудительно заменяем на identity — несжатое тело проще переписывать
    "x-forwarded-for",  # не раскрываем факт проксирования
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
}

# Что удаляем из ответа цели перед отдачей браузеру
STRIP_RESPONSE_HEADERS = HOP_BY_HOP | {
    # Заголовки безопасности — блокируют загрузку контента с localhost
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "strict-transport-security",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    # httpx уже декодировал сжатие, а тело могло измениться после rewriting —
    # эти заголовки пересчитываются/убираются вручную
    "content-encoding",
    "content-length",
}

# Content-Type (без параметров), в теле которых переписываем URL
REWRITE_EXACT_TYPES = {
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "text/javascript",
}

# ---------------------------------------------------------------------------
# URL rewriting
# ---------------------------------------------------------------------------

# Путь вида __<домен>__/<остаток> — маршрутизация на доп. домен
_DOMAIN_PREFIX_RE = re.compile(r"^__([A-Za-z0-9.-]+?)__(?=/|$)")


Rewriter = tuple[re.Pattern, str | Callable[[re.Match], str]]


@lru_cache(maxsize=64)
def _build_rewriters(http_origin: str, ws_origin: str) -> tuple[Rewriter, ...]:
    """
    Компилирует набор (regex, замена) для переписывания всех упоминаний
    целевых доменов и root-relative URL. Кэшируется по origin прокси
    (host:port берётся из заголовка Host запроса, поэтому прокси работает
    на любом порту).

    http_origin — например "http://localhost:8000" или, в режиме JupyterHub,
                  "http://localhost:8080/user/login/proxy/8000" (без слэша
                  на конце; путь в origin — это и есть BASE_PATH)
    ws_origin   — например "ws://localhost:8000"
    """
    host_only = http_origin.split("://", 1)[-1].split("/", 1)[0]  # "localhost:8000"
    base_path = urlparse(http_origin).path.rstrip("/")  # "" или "/user/login/proxy/8000"
    rules: list[Rewriter] = []

    def add(pattern: str, repl: str) -> None:
        rules.append((re.compile(pattern, re.IGNORECASE), repl))

    # Граница после домена: не буква/цифра/_/./- (чтобы не испортить
    # "site.com.evil.net" или "site.com.evil" — но пропустить "site.com/x")
    boundary = r"(?![\w.-])"

    for domain in ALL_DOMAINS:
        # Для доп. доменов путь на прокси получает префикс /__домен__
        pref = "" if domain == TARGET_DOMAIN else f"/__{domain}__"
        d = re.escape(domain)
        http_repl = http_origin + pref
        ws_repl = ws_origin + pref
        esc_repl = http_repl.replace("/", "\\/")  # для JS/JSON: https:\/\/site
        enc_repl = quote(http_repl, safe="")      # для URL-encoded: https%3A%2F%2Fsite

        # Обычные схемы. wss:// -> ws://, т.к. localhost работает по чистому http
        add(rf"https://{d}{boundary}", http_repl)
        add(rf"http://{d}{boundary}", http_repl)
        add(rf"wss://{d}{boundary}", ws_repl)
        add(rf"ws://{d}{boundary}", ws_repl)
        # Экранированные слэши внутри JS-строк и JSON
        add(rf"https:\\/\\/{d}{boundary}", esc_repl)
        add(rf"http:\\/\\/{d}{boundary}", esc_repl)
        # URL-encoded варианты (IGNORECASE ловит %3a и %3A)
        add(rf"https%3a%2f%2f{d}{boundary}", enc_repl)
        add(rf"http%3a%2f%2f{d}{boundary}", enc_repl)
        # Protocol-relative: //site.com/... -> //host<BASE_PATH>/...
        # (?<!:) не даёт зацепиться за хвост уже заменённого "https://site"
        add(rf"(?<!:)//{d}{boundary}", "//" + host_only + base_path + pref)
        # «Голый» домен без схемы — только для основного домена: JS-код часто
        # строит URL конкатенацией ("https://" + host + "/path"). (?<![\w.@-])
        # не трогает поддомены (auth.openai.com) и email-адреса.
        if domain == TARGET_DOMAIN:
            add(rf"(?<![\w.@-]){d}{boundary}", host_only + base_path)

    # --- Root-relative URL ("/wiki/X", "/load.php?...") ---------------------
    # Смысл появляется только при непустом BASE_PATH: без префикса браузер
    # и так разрешает их от корня прокси. Замены добавляются в КОНЕЦ списка
    # (после доменных) и не создают триггерных контекстов друг для друга —
    # повторного префиксования не возникает.
    #
    # Триггеры контекстные: "..." после =/(/:" — поэтому // (protocol-relative),
    # ://, split("/") и JS-регэкспы вида "/\d+/" не затрагиваются.
    if base_path:
        esc_base = base_path.replace("/", "\\/")  # для экранированного JSON
        # Идемпотентность: URL, уже содержащий базовый путь, не префиксуем повторно
        not_base = rf"(?!{re.escape(base_path[1:])}(?:/|$))"
        # Ключ JSON/JS-объекта: "wgArticlePath" или src
        key = r"(?:[A-Za-z_$][\w$]*|[\"'][A-Za-z_$][\w$. \t-]*[\"'])"

        # HTML-атрибуты: href="/wiki/X", src="/w/load.php?...", action="..."
        add(
            r"(\s(?:href|src|action|formaction|poster|background|cite|longdesc"
            r"|data-src|data-url)\s*=\s*)([\"'])/(?!/)" + not_base,
            rf"\g<1>\g<2>{base_path}/",
        )

        # srcset/imagesrcset — список "url дескриптор, url дескриптор, ...":
        # каждый root-relative кандидат префиксуем отдельно (замена-функция,
        # а не строка, т.к. кандидатов много и триггер у них — запятая)
        def _srcset_repl(m: re.Match) -> str:
            head, quote, value = m.group(1), m.group(2), m.group(3)
            tokens = []
            for token in value.split(","):
                stripped = token.lstrip()
                if (
                    stripped.startswith("/")
                    and not stripped.startswith("//")
                    and not stripped.startswith(base_path + "/")
                    and stripped != base_path
                ):
                    indent = token[: len(token) - len(stripped)]
                    token = indent + base_path + stripped
                tokens.append(token)
            return head + quote + ",".join(tokens) + quote

        rules.append((
            re.compile(r"(\s(?:srcset|imagesrcset)\s*=\s*)([\"'])([^\"']*)\2", re.IGNORECASE),
            _srcset_repl,
        ))

        # CSS: url(/static/x.png), url('/x'), url("/x")
        add(r"(url\s*\(\s*([\"'])?)/(?!/)" + not_base, rf"\g<1>{base_path}/")
        # JS-вызовы, где URL — первый аргумент: fetch("/api"), open("/x"),
        # import("/mod"), mw.loader.load("/w/load.php?...")
        add(r"(\b(?:fetch|open|import|load)\s*\(\s*)([\"'])/(?!/)" + not_base, rf"\g<1>\g<2>{base_path}/")
        # XHR: xhr.open("GET", "/x") — URL вторым аргументом
        add(r"(\.open\s*\(\s*[\"'][^\"']*[\"']\s*,\s*)([\"'])/(?!/)" + not_base, rf"\g<1>\g<2>{base_path}/")
        # JSON/JS-объекты: "wgArticlePath": "/wiki/$1", src: "/x"
        add(rf"({key}\s*:\s*)([\"'])/(?!/)" + not_base, rf"\g<1>\g<2>{base_path}/")
        # То же с экранированными слэшами: "wgScript":"\/w\/index.php"
        add(rf'({key}\s*:\s*")\\/(?!/)' + not_base, rf"\g<1>{esc_base}/")

    return tuple(rules)


def rewrite_text(text: str, rewriters: tuple[Rewriter, ...]) -> str:
    for pattern, repl in rewriters:
        text = pattern.sub(repl, text)
    return text


def is_rewritable(content_type: str | None) -> bool:
    """Нужно ли переписывать тело ответа с таким Content-Type."""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if not ct:
        return False
    return (
        ct in REWRITE_EXACT_TYPES
        or ct.startswith("text/")  # html, css, event-stream (SSE), plain...
        or ct.endswith("+json")    # application/ld+json, ...+json
        or ct.endswith("+xml")     # image/svg+xml, application/xhtml+xml
    )


def configure(
    target_url: str | None = None,
    extra_domains: list[str] | None = None,
    base_path: str | None = None,
) -> None:
    """
    Переопределяет целевой сайт (и доп. домены, и базовый путь) на лету,
    без перезапуска процесса. Используется прокси-раннером из Jupyter
    (proxy_runner.start_proxy).

    extra_domains=None означает «оставить как есть», [] — «отключить доп. домены».
    base_path=None — оставить BASE_PATH из config.txt/окружения, "" — отключить
    префикс, "/user/x/proxy/8000" (или полный URL) — включить.
    ВАЖНО: сбрасывает кэш компилятора rewriter'ов — их ключ только origin прокси,
    а список доменов и базовый путь зашиты в сами шаблоны.
    """
    global TARGET_URL, TARGET_DOMAIN, TARGET_SCHEME
    global EXTRA_TARGET_DOMAINS, ALL_DOMAINS, _EXTRA_SET, BASE_PATH

    if target_url:
        TARGET_URL = target_url.rstrip("/")
        _parsed = urlparse(TARGET_URL)
        TARGET_DOMAIN = _parsed.netloc
        TARGET_SCHEME = _parsed.scheme or "https"

    if extra_domains is not None:
        EXTRA_TARGET_DOMAINS = [d.strip() for d in extra_domains if d.strip()]

    if base_path is not None:
        BASE_PATH = normalize_base_path(base_path)

    _EXTRA_SET = set(EXTRA_TARGET_DOMAINS)
    ALL_DOMAINS = [TARGET_DOMAIN, *EXTRA_TARGET_DOMAINS]
    _build_rewriters.cache_clear()


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

def cookie_prefix(domain: str) -> str:
    return f"__{domain}__"


def filter_request_cookies(raw: str, domain: str, is_main: bool) -> str | None:
    """
    Браузер хранит все cookies на одном хосте (localhost), а цельexpects, что
    каждый домен видит только свои. Решение: cookies доп. доменов живут
    под именами "__<домен>__<имя>".

      * Запрос к основному домену  -> пробрасываем cookies БЕЗ префиксов.
      * Запрос к доп. домену       -> пробрасываем только "__<домен>__*",
                                      сняв префикс (иначе CDN получил бы
                                      чужую сессию, а это и утечка, и баг).
    """
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if is_main:
        extra_prefixes = tuple(cookie_prefix(d) for d in EXTRA_TARGET_DOMAINS)
        kept = [p for p in parts if not p.startswith(extra_prefixes)]
    else:
        pref = cookie_prefix(domain)
        kept = [p[len(pref):] for p in parts if p.startswith(pref)]
    return "; ".join(kept) if kept else None


def rewrite_set_cookie(cookie: str, domain: str, is_main: bool) -> str:
    """
    Переписывает Set-Cookie от цели так, чтобы cookie «прижилась» на localhost:
      * убираем Domain=...      — иначе браузер отвергнет cookie для localhost;
      * убираем Secure          — у нас http, cookie с Secure просто не сохранится;
      * SameSite=None -> Lax    — None без Secure браузеры игнорируют;
      * доп. доменам добавляем префикс имени __<домен>__ (см. filter_request_cookies).
    HttpOnly / Path / Max-Age / Expires сохраняются как есть.
    """
    parts = cookie.split(";")
    name_value = parts[0].strip()

    if not is_main:
        name, sep, value = name_value.partition("=")
        name_value = f"{cookie_prefix(domain)}{name.strip()}{sep}{value}"

    attrs: list[str] = []
    for part in parts[1:]:
        attr = part.strip()
        low = attr.lower()
        if low.startswith("domain=") or low == "secure" or low == "partitioned":
            continue
        if low.startswith("path="):
            # В режиме JupyterHub cookie-путь должен включать базовый путь,
            # иначе браузер не пришлёт cookie на /user/.../proxy/8000/wiki/...
            cookie_path = attr.split("=", 1)[1].strip()
            if BASE_PATH and cookie_path.startswith("/") and cookie_path != "/":
                attr = f"Path={BASE_PATH}{cookie_path}"
        if low.startswith("samesite="):
            value = attr.split("=", 1)[1].strip()
            attr = "SameSite=Lax" if value.lower() == "none" else f"SameSite={value}"
        attrs.append(attr)

    return "; ".join([name_value, *attrs])


# ---------------------------------------------------------------------------
# Маршрутизация путей
# ---------------------------------------------------------------------------

def resolve_target(path: str) -> tuple[str, str, bool]:
    """
    Определяет, какому домену соответствует путь.
    Возвращает (домен, upstream-путь со ведущим "/", is_main).
    Путь "/__cdn.oaistatic.com__/x.js" -> ("cdn.oaistatic.com", "/x.js", False).
    Префикс срабатывает только для известных EXTRA_TARGET_DOMAINS —
    родные пути сайта вида /__next__/... не искажаются.
    """
    m = _DOMAIN_PREFIX_RE.match(path)
    if m and m.group(1) in _EXTRA_SET:
        domain = m.group(1)
        rest = path[m.end():].lstrip("/")
        return domain, "/" + rest, False
    return TARGET_DOMAIN, "/" + path.lstrip("/"), True


def raw_request_path(scope) -> str:
    """
    Исходный путь без декодирования %XX — максимальная точность проброса.

    При заданном BASE_PATH uvicorn (root_path) сам подставляет префикс в
    path/raw_path; если префикс пришёл и в самом запросе (например, nginx
    его не отрезал), он удваивается — поэтому снимаем циклом. Путь реального
    сайта (для Википедии) с BASE_PATH пересечься не может.
    """
    raw = scope.get("raw_path") or scope.get("path", "/").encode()
    path = raw.decode("latin-1")
    while BASE_PATH and (path + "/").startswith(BASE_PATH + "/"):
        path = path[len(BASE_PATH):]
    return path.lstrip("/")


def proxy_origins(request: Request) -> tuple[str, str]:
    """
    Origin прокси из фактического запроса: берём Host из заголовка клиента
    (а не из сокета), чтобы localhost и 127.0.0.1 не путали cookie-хранилища.
    Схема — из X-Forwarded-Proto (реальный JupyterHub терминирует TLS),
    иначе схема самого запроса. При заданном BASE_PATH origin включает
    префикс: http://host:8080/user/my_login/proxy/8000.
    Возвращает (http_origin, ws_origin).
    """
    host = request.headers.get("host") or f"{PROXY_HOST}:{PROXY_PORT}"
    scheme = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    if scheme not in ("http", "https"):
        scheme = request.url.scheme  # "http" для чистого uvicorn
    ws_scheme = "ws" if scheme == "http" else "wss"
    return f"{scheme}://{host}{BASE_PATH}", f"{ws_scheme}://{host}{BASE_PATH}"


# ---------------------------------------------------------------------------
# Приложение
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Один клиент на всё приложение: пул соединений, HTTP/2 к цели,
    # редиректы НЕ следуем — отдаём их браузеру с переписанным Location.
    app.state.client = httpx.AsyncClient(
        follow_redirects=False,
        http2=True,
        timeout=httpx.Timeout(connect=15.0, read=600.0, write=120.0, pool=30.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    logger.info(
        "Reverse proxy ready: * -> %s (extra domains: %s)",
        TARGET_URL,
        ", ".join(EXTRA_TARGET_DOMAINS) or "none",
    )
    yield
    await app.state.client.aclose()


app = FastAPI(
    title="Local Reverse Proxy",
    docs_url=None,  # /docs и /openapi.json отключены — эти пути может использовать сам сайт
    redoc_url=None,
    openapi_url=None,
    # root_path здесь — запасной вариант для запуска "uvicorn main:app" без
    # --root-path: uvicorn, получив свой root_path, перепишет scope сам.
    root_path=BASE_PATH,
    lifespan=lifespan,
)


def _error_response(status: int, message: str) -> Response:
    return Response(
        content=f"[reverse-proxy] {message}\n",
        status_code=status,
        media_type="text/plain",
    )


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_http(request: Request, path: str) -> Response:
    domain, upstream_path, is_main = resolve_target(raw_request_path(request.scope))
    upstream_base = TARGET_URL if is_main else f"https://{domain}"

    # Query передаём как сырую строку — без перекодирования параметров
    query = request.scope.get("query_string", b"").decode("latin-1")
    url = f"{upstream_base}{upstream_path}" + (f"?{query}" if query else "")

    http_origin, ws_origin = proxy_origins(request)
    rewriters = _build_rewriters(http_origin, ws_origin)

    # --- Заголовки запроса -------------------------------------------------
    fwd: list[tuple[bytes, bytes]] = []
    for key_b, value_b in request.headers.raw:
        key = key_b.decode("latin-1")
        low = key.lower()
        if low in STRIP_REQUEST_HEADERS:
            continue
        if low == "cookie":
            filtered = filter_request_cookies(value_b.decode("latin-1"), domain, is_main)
            if filtered:
                fwd.append((b"cookie", filtered.encode("latin-1")))
            continue
        if low == "origin":
            # Цель ждёт свой origin; localhost тут раскрыл бы проксирование (CSRF-проверки)
            value = value_b.decode("latin-1")
            # Браузер шлёт Origin без пути, поэтому сравниваем и с вариантом
            # без BASE_PATH (http_origin содержит префикс)
            stripped = value.rstrip("/")
            bare_origin = http_origin[: -len(BASE_PATH)] if BASE_PATH else http_origin
            if stripped == http_origin or stripped == bare_origin:
                value = f"{TARGET_SCHEME if is_main else 'https'}://{domain}"
            fwd.append((key.encode(), value.encode("latin-1")))
            continue
        if low == "referer":
            # Referer: http://localhost:8000/x -> https://target/x
            value = value_b.decode("latin-1")
            if value == http_origin or value.startswith(http_origin + "/"):
                value = upstream_base + value[len(http_origin):]
            fwd.append((key.encode(), value.encode("latin-1")))
            continue
        fwd.append((key_b, value_b))

    # Просим несжатый ответ — regex-rewriting по plain-text сильно надёжнее.
    # Если цель всё же сожмёт (Cloudflare любит), httpx сам декодирует.
    fwd.append((b"accept-encoding", b"identity"))

    # --- Тело запроса -------------------------------------------------------
    # Сырые байты как есть: JSON, form-urlencoded и multipart/form-data
    # (включая upload файлов) пробрасываются без разбора — boundary живёт
    # в нетронутом Content-Type.
    body = await request.body()
    content = body if (body or request.method in ("POST", "PUT", "PATCH", "DELETE")) else None

    client: httpx.AsyncClient = request.app.state.client
    upstream_request = client.build_request(request.method, url, headers=fwd, content=content)

    try:
        upstream = await client.send(upstream_request, stream=True)
    except httpx.TimeoutException as exc:
        logger.warning("Upstream timeout for %s %s: %s", request.method, url, exc)
        return _error_response(504, f"upstream timeout: {exc}")
    except httpx.HTTPError as exc:
        logger.warning("Upstream error for %s %s: %s", request.method, url, exc)
        return _error_response(502, f"upstream error: {exc}")

    logger.info("%s /%s -> %s -> %s", request.method, path, domain, upstream.status_code)

    # --- Заголовки ответа ---------------------------------------------------
    out_headers: list[tuple[bytes, bytes]] = []
    # Set-Cookie может повторяться — обрабатываем каждый отдельно
    for sc in upstream.headers.get_list("set-cookie"):
        rewritten = rewrite_set_cookie(sc, domain, is_main)
        out_headers.append((b"set-cookie", rewritten.encode("latin-1")))
        logger.debug("Set-Cookie: %s -> %s", sc, rewritten)

    for key_b, value_b in upstream.headers.raw:
        low = key_b.decode("latin-1").lower()
        if low in STRIP_RESPONSE_HEADERS or low == "set-cookie":
            continue
        value = value_b.decode("latin-1")
        if low == "location":
            # Редирект: цель вернула абсолютный URL — переписываем на прокси,
            # относительный оставляем (браузер сам резолвит его от localhost).
            value = rewrite_text(value, rewriters)
            if BASE_PATH and value.startswith("/") and not value.startswith("//"):
                # Root-relative Location браузер резолвит от корня хоста,
                # а в режиме JupyterHub прокси живёт под префиксом
                value = BASE_PATH + value
        out_headers.append((key_b, value.encode("latin-1")))

    no_body = (
        request.method == "HEAD"
        or upstream.status_code in (204, 304)
        or 100 <= upstream.status_code < 200
    )

    try:
        if no_body:
            await upstream.aclose()
            resp = Response(status_code=upstream.status_code)
            resp.raw_headers = out_headers
            return resp

        if is_rewritable(upstream.headers.get("content-type")):
            # Текстовые ответы (включая SSE) читаем целиком и переписываем.
            body_bytes = await upstream.aread()
            if len(body_bytes) <= MAX_REWRITE_BODY_SIZE:
                try:
                    text = body_bytes.decode("utf-8")
                    body_bytes = rewrite_text(text, rewriters).encode("utf-8")
                except UnicodeDecodeError:
                    # текстовый Content-Type, но тело не utf-8 — отдаём как есть
                    pass
            out_headers.append((b"content-length", str(len(body_bytes)).encode()))
            resp = Response(content=body_bytes, status_code=upstream.status_code)
            resp.raw_headers = out_headers
            return resp

        # Бинарное (картинки, шрифты, видео, архивы) — стримим чанками,
        # не буферизуя целиком.
        async def stream_body():
            try:
                async for chunk in upstream.aiter_bytes():
                    yield chunk
            finally:
                await upstream.aclose()

        resp = StreamingResponse(stream_body(), status_code=upstream.status_code)
        resp.raw_headers = out_headers
        return resp
    except Exception:
        await upstream.aclose()
        raise


# ---------------------------------------------------------------------------
# WebSocket-прокси
# ---------------------------------------------------------------------------

@app.websocket("/{path:path}")
async def proxy_ws(ws: WebSocket, path: str) -> None:
    domain, upstream_path, is_main = resolve_target(raw_request_path(ws.scope))

    # Основной домен наследует схему таргета (https -> wss), доп. домены — https/wss
    scheme = "wss" if (is_main and TARGET_SCHEME == "https" or not is_main) else "ws"
    query = ws.scope.get("query_string", b"").decode("latin-1")
    uri = f"{scheme}://{domain}{upstream_path}" + (f"?{query}" if query else "")

    # Заголовки хендшейка с целью: подменяем Origin на «родной» для сайта,
    # иначе сервер отвергнет соединение как чужое. Host НЕ подставляем —
    # websockets выставит его сам из URI (дубликат Host -> HTTP 400).
    # Cookies — с тем же namespace, что и в HTTP-части.
    handshake: list[tuple[str, str]] = [
        ("Origin", f"{'https' if scheme == 'wss' else 'http'}://{domain}"),
    ]
    for name in ("user-agent", "accept-language", "authorization"):
        value = ws.headers.get(name)
        if value:
            handshake.append((name, value))

    cookie_header = ws.headers.get("cookie")
    if cookie_header:
        filtered = filter_request_cookies(cookie_header, domain, is_main)
        if filtered:
            handshake.append(("Cookie", filtered))

    connect_kwargs: dict = {
        "open_timeout": 20,
        "close_timeout": 5,
        # большие фреймы (стриминг ответов модели) не должны обрезаться
        "max_size": 2**24,
        # вебсокеты-библиотека должна жить не дольше, чем соединение клиента
        "ping_interval": 20,
        "ping_timeout": 20,
    }
    # Субпротоколы пробрасываем только если клиент их запросил: пустой список
    # subprotocols=[] ломает хендшейк (клиент websockets шлёт некорректный заголовок).
    # ВАЖНО: у Starlette WebSocket нет свойства .subprotocols — берём из ASGI-scope.
    subprotocols = list(ws.scope.get("subprotocols") or [])
    if subprotocols:
        connect_kwargs["subprotocols"] = subprotocols
    if _NEW_WS_API:
        connect_kwargs["additional_headers"] = handshake
    else:
        connect_kwargs["extra_headers"] = handshake

    try:
        upstream = await _ws_connect(uri, **connect_kwargs)
    except Exception as exc:
        logger.warning("WS upstream connect failed %s: %s", uri, exc)
        await ws.accept()
        await ws.close(code=1011)  # internal error — цель недоступна
        return

    # Если цель выбрала субпротокол — повторяем его клиенту
    chosen = getattr(upstream, "subprotocol", None)
    await ws.accept(subprotocol=chosen)
    logger.info("WS /%s -> %s (subprotocol=%s)", path, uri, chosen)

    upstream_close_code = 1000

    async def client_to_upstream() -> None:
        try:
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    return
                if msg["type"] == "websocket.receive":
                    if msg.get("text") is not None:
                        await upstream.send(msg["text"])
                    elif msg.get("bytes") is not None:
                        await upstream.send(msg["bytes"])
        except Exception:
            # клиент пропал / соединение уже закрыто — тихо завершаем насос
            return

    async def upstream_to_client() -> None:
        nonlocal upstream_close_code
        try:
            while True:
                msg = await upstream.recv()
                if isinstance(msg, str):
                    await ws.send_text(msg)
                else:
                    await ws.send_bytes(msg)
        except ConnectionClosed as exc:
            upstream_close_code = exc.code or 1000
        except Exception:
            return

    t_up = asyncio.create_task(upstream_to_client())
    t_down = asyncio.create_task(client_to_upstream())
    try:
        # Крутим оба насоса, пока жив хотя бы один; как только один закрылся —
        # гасим второй и закрываем обе стороны с симметричным close-code.
        _done, pending = await asyncio.wait(
            {t_up, t_down}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        with suppress(Exception):
            await upstream.close()
        with suppress(Exception):
            await ws.close(code=upstream_close_code)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=PROXY_HOST,
        port=PROXY_PORT,
        root_path=BASE_PATH,
        log_level="debug" if DEBUG else "info",
    )
