# hydra_project/asgi.py
import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import re_path
from security_hud.consumers import HydraHUDConsumer

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hydra_project.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter([
            re_path(r'^hud/ws/$', HydraHUDConsumer.as_asgi()),
        ])
    ),
})
