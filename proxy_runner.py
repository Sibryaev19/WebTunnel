"""
Запуск reverse proxy из Jupyter-ноутбука одной функцией.

Пример:
    from proxy_runner import start_proxy, stop_proxy
    server = start_proxy("https://ru.wikipedia.org", port=8899)
    ...
    stop_proxy()

    # режим JupyterHub (сайт доступен под префиксом):
    server = start_proxy("https://ru.wikipedia.org", port=8899,
                         base_path="/user/my_login/proxy/8899")

Прокси работает в фоновом потоке: в ноутбуке уже крутится свой event loop,
поэтому uvicorn'у выделяется отдельный поток со своим loop.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import uvicorn

# Гарантируем, что main.py импортируется, даже если ядро ноутбука
# запущено из другой рабочей директории.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import main  # noqa: E402

_STATE: dict = {}


def start_proxy(
    target_url: str,
    *,
    port: int | None = None,
    host: str | None = None,
    extra_domains: list[str] | None = None,
    base_path: str | None = None,
    debug: bool | None = None,
) -> uvicorn.Server:
    """
    Запускает прокси в фоновом потоке и возвращает объект uvicorn.Server.

    target_url     — целевой сайт, напр. "https://ru.wikipedia.org" (обязательный
                     аргумент).
    port, host     — где слушать; None = значения из config (config.txt / окружение).
                     Origin для переписывания URL вычисляется из фактического Host
                     запроса, поэтому прокси корректно работает на любом порту.
    extra_domains  — доп. домены (CDN/SSO), доступны как /__<домен>__/...
                     None = значения по умолчанию из config,
                     []   = отключить доп. домены.
    base_path      — префикс JupyterHub, напр. "/user/my_login/proxy/8899"
                     (можно и полный URL — будет взят путь). None = BASE_PATH из
                     config, "" = отключить префикс. Все ссылки переписываются
                     с учётом префикса, uvicorn получает root_path.
    debug          — подробные логи; None = из config.

    Повторный вызов сам останавливает предыдущий инстанс.
    """
    stop_proxy()

    import config as cfg

    if port is None:
        port = cfg.PROXY_PORT
    if host is None:
        host = cfg.PROXY_HOST
    if debug is None:
        debug = cfg.DEBUG

    main.configure(target_url=target_url, extra_domains=extra_domains, base_path=base_path)
    # app-level root_path — запасной вариант, если прокси запущен без uvicorn
    # root_path; синхронизируем на случай, когда base_path пришёл аргументом
    main.app.root_path = main.BASE_PATH

    server = uvicorn.Server(
        uvicorn.Config(
            main.app,
            host=host,
            port=port,
            root_path=main.BASE_PATH,
            log_level="debug" if debug else "info",
        )
    )
    thread = threading.Thread(
        target=server.run, daemon=True, name=f"reverse-proxy:{port}"
    )
    thread.start()

    # Ждём фактического старта: ошибка «порт занят» должна упасть здесь
    # с понятным текстом, а не молча в фоновом потоке.
    deadline = time.monotonic() + 15
    while not server.started:
        if not thread.is_alive():
            raise RuntimeError(
                f"Прокси не смог стартовать на {host}:{port} — вероятно, "
                "порт занят другим процессом (см. лог выше)."
            )
        if time.monotonic() > deadline:
            raise RuntimeError(f"Прокси не поднялся за 15 с на {host}:{port}.")
        time.sleep(0.1)

    _STATE["server"] = server
    _STATE["thread"] = thread

    base = f"http://{host}:{port}{main.BASE_PATH}"
    print(f"Прокси запущен: {base}  ->  {target_url}")
    for d in main.EXTRA_TARGET_DOMAINS:
        print(f"   доп. домен: {base}/__{d}__/...")
    print("Остановка: stop_proxy()")
    return server


def stop_proxy(timeout: float = 5.0) -> None:
    """Аккуратно останавливает запущенный прокси (если он был запущен)."""
    server = _STATE.get("server")
    if server is None:
        return
    server.should_exit = True
    _STATE["thread"].join(timeout=timeout)
    _STATE.clear()
    print("Прокси остановлен.")
