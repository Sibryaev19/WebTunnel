from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods


# Страница 403, которую отдаёт HUE при провале CSRF-проверки
HUE_CSRF_PAGE = (
    "CSRF error.\n"
    "Sorry, your session is invalid or has expired. Please go back, "
    "refresh the page, and try your submission again."
)


def csrf_failure(request, reason="", template_name=None):
    return HttpResponse(HUE_CSRF_PAGE, status=403)


@login_required
def home(request):
    return render(request, "hueapp/home.html", {"csrf_cookie_name": settings.CSRF_COOKIE_NAME})


@require_http_methods(["POST"])
@login_required
def session_check(request):
    """AJAX-эндпоинт, который реальный Hue дергает сразу после загрузки
    страницы (проверка конфигурации/сессии). CSRF-защита — дефолтная."""
    return JsonResponse({"ok": True, "user": request.user.username})


@login_required
def execute(request):
    """Обычная форма (аналог отправки запроса в Hive-редакторе HUE)."""
    query = request.POST.get("query", "")
    return render(request, "hueapp/executed.html", {"query": query})
