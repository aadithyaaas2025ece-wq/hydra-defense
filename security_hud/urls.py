# security_hud/urls.py
from django.urls import path
from . import views

app_name = 'hud'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
]
