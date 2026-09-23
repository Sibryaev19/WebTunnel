from django.contrib.auth.views import LoginView
from django.urls import path

from hueapp import views

urlpatterns = [
    path("", views.home, name="home"),
    path("accounts/login/", LoginView.as_view(template_name="hueapp/login.html"), name="login"),
    path("api/session_check", views.session_check, name="session_check"),
    path("execute", views.execute, name="execute"),
]
