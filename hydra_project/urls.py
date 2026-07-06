# hydra_project/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls', namespace='core')),
    path('hud/', include('security_hud.urls', namespace='hud')),
    path('api/', include('core.api_urls')),
]
