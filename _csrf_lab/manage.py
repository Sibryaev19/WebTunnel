#!/usr/bin/env python3
"""Мини-стенд «псевдо-HUE»: Django-приложение с типовой CSRF-защитой.

Реальный HUE написан на Django; эта заглушка воспроизводит его ключевые
механики: форма логина с {% csrf_token %}, ротация CSRF-токена при логине
(django.contrib.auth.login -> rotate_token), AJAX POST c заголовком
X-CSRFToken (как Hue UI) и обычная форма с токеном.

Запуск:
    .venv/bin/python manage.py runserver 127.0.0.1:8888 --noreload
Логин/пароль тестового пользователя: tester / hue-pass-123
"""
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pseudo_hue.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
