# security_hud/views.py
from django.shortcuts import render
from ai_agents.event_store import EventStore


def dashboard(request):
    store = EventStore()
    return render(request, 'hud/dashboard.html', {
        'stats': store.stats(),
        'recent_events': store.recent(20),
    })
