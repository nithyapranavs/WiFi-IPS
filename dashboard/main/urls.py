
from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("home/", views.index, name="index"),
    path("logs/", views.attack_logs, name="logs"),
    path("detection/", views.detection_views, name="detection"),
    path("prevention/", views.prevention_views, name="prevention"),
    path("clients_connected", views.clients_connected, name="clients_connected"),
    path("settings/", views.settings, name="settings"),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
]
