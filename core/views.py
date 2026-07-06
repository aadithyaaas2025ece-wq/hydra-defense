"""
CORE APP VIEWS — Demo targets for the Hydra Defense system.
These views are INTENTIONALLY simplified to show the middleware working.
In a real app, replace these with your actual views.
"""

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import UserProfile
import json


def home(request):
    """Home page — shows different content based on threat status."""
    in_shadow = request.session.get('in_shadow_realm', False)
    verdict = getattr(request, 'hydra_verdict', None)

    context = {
        'in_shadow_realm': in_shadow,
        'threat_score': request.session.get('threat_score', 0),
        'hydra_action': request.session.get('hydra_action', 'allow'),
        'verdict': verdict,
    }
    return render(request, 'core/home.html', context)


def search(request):
    """
    Search page — primary SQL injection target.
    In Shadow Realm: returns fake results from poison DB.
    Normal users: returns real results.
    """
    results = []
    query = request.GET.get('q', '')
    in_shadow = request.session.get('in_shadow_realm', False)

    if query:
        # Safe ORM query — Shadow Realm routing handled by DB router
        # A quarantined attacker will get results from the shadow DB
        try:
            results = list(UserProfile.objects.filter(
                display_name__icontains=query
            ).values('display_name', 'bio', 'location')[:20])
        except Exception:
            results = []

    return render(request, 'core/search.html', {
        'query': query,
        'results': results,
        'in_shadow_realm': in_shadow,
        'result_count': len(results),
    })


def login_view(request):
    """Login page — primary brute force target."""
    error = None
    in_shadow = request.session.get('in_shadow_realm', False)

    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')

        if in_shadow:
            # Fake successful login for attackers in Shadow Realm
            request.session['fake_logged_in'] = True
            request.session['fake_username'] = username
            return redirect('core:shadow_success')

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('core:home')
        else:
            error = "Invalid credentials"

    return render(request, 'core/login.html', {
        'error': error,
        'in_shadow_realm': in_shadow,
    })


def shadow_success(request):
    """Fake success page for quarantined attackers — they think they're in!"""
    if not request.session.get('fake_logged_in'):
        return redirect('core:login')

    # Import honeypot data
    from ai_agents.honeypot import POISON_DATASET

    return render(request, 'core/shadow_success.html', {
        'username': request.session.get('fake_username', 'admin'),
        'fake_users': POISON_DATASET['users'][:10],
        'fake_transactions': POISON_DATASET['transactions'][:5],
    })


def api_status(request):
    """Quick API endpoint to check Hydra status."""
    from ai_agents.event_store import EventStore
    store = EventStore()
    return JsonResponse({
        'status': 'active',
        'stats': store.stats(),
        'recent_count': len(store.recent(10)),
    })
