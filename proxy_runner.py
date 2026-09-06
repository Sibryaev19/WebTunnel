"""
Запуск reverse proxy из Jupyter-ноутбука одной функцией.

Пример:
    from proxy_runner import start_proxy, stop_proxy
    server = start_proxy("https://ru.wikipedia.org", port=8899)
    ...
    stop_proxy()

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
    port: int = 8000,
    host: str = "127.0.0.1",
    extra_domains: list[str] | None = None,
    debug: bool = False,
) -> uvicorn.Server:
    """
    Запускает прокси в фоновом потоке и возвращает объект uvicorn.Server.

    target_url     — целевой сайт, напр. "https://chatgpt.com" или
                     "https://ru.wikipedia.org" (обязательный аргумент).
    port, host     — где слушать. Origin для переписывания URL вычисляется
                     из фактического Host запроса, поэтому прокси корректно
                     работает на любом порту (8000 на этой машине занят
                     другим сервисом — берите другой).
    extra_domains  — доп. домены (CDN/SSO), доступны как /__<домен>__/...
                     None = значения по умолчанию из main.py,
                     []   = отключить доп. домены.
    debug          — подробные логи.

    Повторный вызов сам останавливает предыдущий инстанс.
    """
    stop_proxy()

    main.configure(target_url=target_url, extra_domains=extra_domains)

    server = uvicorn.Server(
        uvicorn.Config(
            main.app,
            host=host,
            port=port,
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

    print(f"Прокси запущен: http://{host}:{port}  ->  {target_url}")
    for d in main.EXTRA_TARGET_DOMAINS:
        print(f"   доп. домен: http://{host}:{port}/__{d}__/...")
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
