"""
HYDRA GATEKEEPER MIDDLEWARE
Intercepts every HTTP request, runs it through the multi-agent AI,
and routes it to the real site OR the Shadow Realm.
"""

import json
import logging
import hashlib
from collections import defaultdict
from datetime import datetime, timedelta
from django.conf import settings
from django.http import HttpResponseForbidden, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from .gatekeeper import HydraGatekeeper
from .event_store import EventStore

logger = logging.getLogger('hydra')

# In-memory request frequency tracker (use Redis in production)
_request_log: dict[str, list] = defaultdict(list)


def get_request_count(ip: str, window_minutes: int = 5) -> int:
    """Count requests from an IP in the last N minutes."""
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    _request_log[ip] = [t for t in _request_log[ip] if t > cutoff]
    _request_log[ip].append(datetime.utcnow())
    return len(_request_log[ip])


def get_client_ip(request) -> str:
    """Extract real IP, handling proxies."""
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def extract_request_data(request) -> dict:
    """Flatten the Django request into a plain dict for agents."""
    ip = get_client_ip(request)

    # Safely extract POST data
    post_data = {}
    try:
        post_data = dict(request.POST)
        # Flatten single-item lists
        post_data = {k: v[0] if isinstance(v, list) and len(v) == 1 else v
                     for k, v in post_data.items()}
    except Exception:
        pass

    # Extract GET params
    get_params = dict(request.GET)
    get_params = {k: v[0] if isinstance(v, list) and len(v) == 1 else v
                  for k, v in get_params.items()}

    # Selected headers (don't log everything for privacy)
    headers = {
        'User-Agent': request.META.get('HTTP_USER_AGENT', ''),
        'Accept-Language': request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        'Accept-Encoding': request.META.get('HTTP_ACCEPT_ENCODING', ''),
        'Referer': request.META.get('HTTP_REFERER', ''),
        'Connection': request.META.get('HTTP_CONNECTION', ''),
        'Content-Type': request.META.get('CONTENT_TYPE', ''),
    }

    return {
        'ip': ip,
        'path': request.path,
        'method': request.method,
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        'referrer': request.META.get('HTTP_REFERER', ''),
        'post_data': post_data,
        'get_params': get_params,
        'headers': headers,
        'request_count': get_request_count(ip),
        'session_key': request.session.session_key,
        'is_ajax': request.headers.get('X-Requested-With') == 'XMLHttpRequest',
        # These would come from JS fingerprinting in production:
        'js_fingerprint': request.session.get('js_fingerprint', False),
        'mouse_moved': request.session.get('mouse_moved', False),
    }


class HydraGatekeeperMiddleware(MiddlewareMixin):
    """
    The Hydra's main interceptor.

    Flow:
      1. Skip whitelisted IPs and static paths
      2. Check if IP is already quarantined (skip AI for known threats)
      3. Run full multi-agent AI evaluation
      4. Apply action: allow / monitor / quarantine / block
    """

    def __init__(self, get_response):
        super().__init__(get_response)
        self.gatekeeper = HydraGatekeeper()
        self.event_store = EventStore()
        self.config = settings.HYDRA_CONFIG
        logger.info("[Hydra] 🐍 Gatekeeper middleware initialized")

    def process_request(self, request):
        """Called before the view. Can return a response to short-circuit."""
        ip = get_client_ip(request)
        path = request.path

        # ── Skip checks ────────────────────────────────────────────────────
        if ip in self.config['WHITELIST_IPS']:
            return None  # Fast pass for trusted IPs

        for skip in self.config['SKIP_PATHS']:
            if path.startswith(skip):
                return None  # Skip static files, websockets, etc.

        # ── Fast path: already quarantined this session? ───────────────────
        if request.session.get('hydra_action') == 'quarantine':
            request.session['in_shadow_realm'] = True
            logger.debug(f"[Hydra] {ip} already in Shadow Realm — skipping re-analysis")
            return None

        if request.session.get('hydra_action') == 'block':
            return HttpResponseForbidden(
                "Access Denied. Your activity has been flagged and logged.",
                content_type='text/plain'
            )

        # ── Full AI evaluation ─────────────────────────────────────────────
        request_data = extract_request_data(request)
        verdict = self.gatekeeper.evaluate(request_data)

        # Store the verdict for the HUD
        self.event_store.push(verdict)

        # Broadcast to live HUD via WebSocket
        self._broadcast_to_hud(verdict)

        action = verdict['action']
        score = verdict['final_score']

        # ── Apply verdict ──────────────────────────────────────────────────

        if action == 'block':
            request.session['hydra_action'] = 'block'
            logger.warning(f"[Hydra] 🚫 BLOCKED {ip} | score={score:.3f} | path={path}")
            return HttpResponseForbidden(
                "Access Denied.",
                content_type='text/plain'
            )

        elif action == 'quarantine':
            request.session['hydra_action'] = 'quarantine'
            request.session['in_shadow_realm'] = True
            request.session['threat_score'] = score
            logger.warning(f"[Hydra] 🕳️ QUARANTINED {ip} | score={score:.3f} | Moved to Shadow Realm")

        elif action == 'monitor':
            request.session['hydra_action'] = 'monitor'
            request.session['threat_score'] = score
            logger.info(f"[Hydra] 👁️ MONITORING {ip} | score={score:.3f}")

        else:
            # Allow — reset any previous flags if this was a monitor
            if request.session.get('hydra_action') == 'monitor':
                request.session['threat_score'] = score
            logger.debug(f"[Hydra] ✅ ALLOWED {ip} | score={score:.3f}")

        # Attach verdict to request so views can access it
        request.hydra_verdict = verdict
        return None  # Continue to view

    def _broadcast_to_hud(self, verdict: dict):
        """Send event to the live security HUD via Django Channels."""
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync

            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                "hydra_hud",
                {
                    "type": "security.event",
                    "data": verdict,
                }
            )
        except Exception as e:
            logger.debug(f"[Hydra] HUD broadcast skipped: {e}")
