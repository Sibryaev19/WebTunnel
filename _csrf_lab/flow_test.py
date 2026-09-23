#!/usr/bin/env python3
"""End-to-end проверка логин-флоу «псевдо-HUE» через прокси.

Имитирует браузер: хранит cookies из Set-Cookie (в https-режиме — с
атрибутами как есть), отправляет форму логина, следует за редиректом и
выполняет AJAX POST c X-CSRFToken из cookie — то, что у реального HUE
ломалось страницей «CSRF error».

    .venv/bin/python _csrf_lab/flow_test.py <base_url> [https]
Примеры:
    .venv/bin/python _csrf_lab/flow_test.py http://127.0.0.2:8900/user/tester/proxy/8900 https
    .venv/bin/python _csrf_lab/flow_test.py http://127.0.0.2:8900/user/tester/proxy/8900
"""
import re
import sys

import httpx

BASE = sys.argv[1].rstrip("/")
HEADERS = {"X-Forwarded-Proto": "https"} if len(sys.argv) > 2 else {}

cookies: dict[str, str] = {}


def absorb(resp: httpx.Response) -> None:
    for sc in resp.headers.get_list("set-cookie"):
        pair = sc.split(";", 1)[0]
        name, _, value = pair.partition("=")
        if not _:
            continue
        cookies[name.strip()] = value.strip()


def cookie_header() -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


with httpx.Client(follow_redirects=False, timeout=10, headers=HEADERS) as client:
    # 1. Страница логина
    r = client.get(f"{BASE}/accounts/login/")
    absorb(r)
    print(f"GET  login  -> {r.status_code}")
    token = re.search(r'csrfmiddlewaretoken" value="([^"]+)"', r.text).group(1)

    # 2. POST логина (Django при успехе ротирует csrftoken и sessionid)
    r = client.post(
        f"{BASE}/accounts/login/?next=/",
        data={"csrfmiddlewaretoken": token, "username": "tester", "password": "hue-pass-123"},
        headers={
            **HEADERS,
            "Cookie": cookie_header(),
            "Referer": f"{BASE}/accounts/login/",
        },
    )
    absorb(r)
    print(f"POST login  -> {r.status_code} (ждём 302)")
    assert r.status_code == 302, f"FAIL: логин не прошёл, статус {r.status_code}:\n{r.text[:300]}"

    # 3. Главная после редиректа
    r = client.get(f"{BASE}/", headers={**HEADERS, "Cookie": cookie_header()})
    absorb(r)
    print(f"GET  home   -> {r.status_code} (ждём 200)")
    assert r.status_code == 200, f"FAIL: главная не открылась: {r.status_code}"
    assert "Вы вошли как tester" in r.text, "FAIL: на главной нет признака логина"

    # 4. AJAX-запрос с X-CSRFToken из (ротированной) cookie — то, что падало у HUE
    csrf = next(v for k, v in cookies.items() if k.endswith("csrftoken"))
    r = client.post(
        f"{BASE}/api/session_check",
        headers={**HEADERS, "Cookie": cookie_header(), "X-CSRFToken": csrf},
    )
    print(f"POST ajax   -> {r.status_code} (ждём 200)")
    assert r.status_code == 200, f"FAIL: AJAX отклонён по CSRF:\n{r.text[:300]}"

print("OK: логин, ротация токена и AJAX-CSRF работают через прокси")
