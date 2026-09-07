#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Конфигурация reverse proxy.

Приоритет источников (от высшего к низшему):
    1. Переменные окружения (TARGET_URL, BASE_PATH, ...)
    2. Файл config.txt, лежащий рядом с этим модулем
    3. Значения по умолчанию из _DEFAULTS

Формат config.txt — по одному параметру на строку:

    KEY=VALUE

Строки, начинающиеся с #, и пустые строки игнорируются; значения можно
брать в одинарные или двойные кавычки. Шаблон файла — config.txt в корне
проекта (все ключи там закомментированы).
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

_CONFIG_FILE = Path(__file__).resolve().parent / "config.txt"

# Значения по умолчанию (действуют, если параметр не задан ни в окружении,
# ни в config.txt).
_DEFAULTS: dict[str, str] = {
    "TARGET_URL": "https://ru.wikipedia.org",
    "EXTRA_TARGET_DOMAINS": "",
    "PROXY_HOST": "127.0.0.1",
    "PROXY_PORT": "8000",
    "MAX_REWRITE_BODY_SIZE": str(8 * 1024 * 1024),
    "DEBUG": "",
    "BASE_PATH": "",
}


def _read_config_file(path: Path) -> dict[str, str]:
    """Читает простые KEY=VALUE-строки; комментарии и пустые строки пропускает."""
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


_FILE_VALUES = _read_config_file(_CONFIG_FILE)


def _raw(key: str) -> str:
    """Значение параметра: окружение > config.txt > дефолт."""
    return os.environ.get(key, _FILE_VALUES.get(key, _DEFAULTS[key])).strip()


def _as_bool(key: str) -> bool:
    return _raw(key).lower() in ("1", "true", "yes", "on")


def _as_int(key: str) -> int:
    raw = _raw(key)
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(
            f"config: параметр {key}={raw!r} не является целым числом — "
            "проверьте config.txt и переменные окружения"
        ) from None


def normalize_base_path(raw: str | None) -> str:
    """
    Нормализует BASE_PATH к виду '/user/my_login/proxy/8000':

      * "" или "/"   -> ""  (обычный localhost без префикса);
      * полный URL   -> берётся только путь (хост всё равно определяется
                        по фактическому Host-заголовку запроса);
      * 'user/x'     -> '/user/x' (добавляется ведущий слэш);
      * хвостовой '/' срезается.
    """
    value = (raw or "").strip()
    if "://" in value:
        value = urlparse(value).path
    value = value.strip().rstrip("/")
    if not value or value == "/":
        return ""
    if not value.startswith("/"):
        value = "/" + value
    return value


TARGET_URL = _raw("TARGET_URL").rstrip("/") or _DEFAULTS["TARGET_URL"]

EXTRA_TARGET_DOMAINS = [
    d.strip() for d in _raw("EXTRA_TARGET_DOMAINS").split(",") if d.strip()
]

PROXY_HOST = _raw("PROXY_HOST")
PROXY_PORT = _as_int("PROXY_PORT")

MAX_REWRITE_BODY_SIZE = _as_int("MAX_REWRITE_BODY_SIZE")

DEBUG = _as_bool("DEBUG")

BASE_PATH = normalize_base_path(_raw("BASE_PATH"))
