"""Настройки стенда. Стандартный Django-набор, максимально близкий к Hue:
сессии и CSRF в cookies (не в БД), SameSite по умолчанию, токен в форме.
SECRET_KEY фиксированный — как у стационарно развёрнутого HUE.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "csrf-lab-only-not-secret"
DEBUG = True
ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "pseudo_hue.urls"
WSGI_APPLICATION = "pseudo_hue.wsgi.application"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "hueapp",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": [
            "django.template.context_processors.request",
            "django.contrib.auth.context_processors.auth",
        ]},
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# Текст ошибки ровно как у HUE (шаблон 403 CSRF-страницы)
CSRF_FAILURE_VIEW = "hueapp.views.csrf_failure"

# Варианты корпоративных конфигураций включаются переменными окружения:
# COOKIE_VARIANT=secure    — cookies с Secure (сайт за TLS-балансиром)
# COOKIE_VARIANT=host      — __Host-префиксы + Secure (строгая политика)
import os

_variant = os.environ.get("COOKIE_VARIANT", "plain")
if _variant == "secure":
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
elif _variant == "host":
    CSRF_COOKIE_NAME = "__Host-csrftoken"
    SESSION_COOKIE_NAME = "__Host-sessionid"
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

USE_TZ = True
STATIC_URL = "static/"
