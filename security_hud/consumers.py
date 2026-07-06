"""
HYDRA HUD WEBSOCKET CONSUMER
Streams real-time security events to the browser dashboard.
Uses Django Channels (ASGI).
"""

import json
import logging
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async

logger = logging.getLogger('hydra')


class HydraHUDConsumer(AsyncWebsocketConsumer):
    """
    WebSocket endpoint: ws://your-site/hud/ws/
    All connected HUD clients join the 'hydra_hud' group
    and receive security events in real time.
    """

    GROUP_NAME = "hydra_hud"

    async def connect(self):
        await self.channel_layer.group_add(self.GROUP_NAME, self.channel_name)
        await self.accept()
        logger.info("[HUD] Client connected to live feed")

        # Send recent events immediately on connect
        recent = await self._get_recent_events()
        await self.send(text_data=json.dumps({
            "type": "history",
            "events": recent,
            "stats": await self._get_stats(),
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.GROUP_NAME, self.channel_name)
        logger.info("[HUD] Client disconnected")

    async def receive(self, text_data):
        """Handle messages from the browser (e.g., clear events, filter)."""
        try:
            data = json.loads(text_data)
            if data.get('action') == 'clear':
                from ai_agents.event_store import EventStore
                EventStore().clear()
                await self.send(text_data=json.dumps({"type": "cleared"}))
        except json.JSONDecodeError:
            pass

    # ─── Group message handlers ──────────────────────────────────────────

    async def security_event(self, event):
        """Broadcast a new security event to this client."""
        await self.send(text_data=json.dumps({
            "type": "event",
            "data": event["data"],
            "stats": await self._get_stats(),
        }))

    # ─── Helpers ─────────────────────────────────────────────────────────

    @database_sync_to_async
    def _get_recent_events(self):
        from ai_agents.event_store import EventStore
        return EventStore().recent(50)

    @database_sync_to_async
    def _get_stats(self):
        from ai_agents.event_store import EventStore
        return EventStore().stats()
