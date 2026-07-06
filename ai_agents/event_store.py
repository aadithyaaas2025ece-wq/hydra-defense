"""
HYDRA EVENT STORE
Keeps the last N security events in memory for the live HUD.
Thread-safe, no database needed.
"""

import threading
from collections import deque
from datetime import datetime


class EventStore:
    """
    Simple thread-safe ring buffer for security events.
    Shared singleton across all middleware instances.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._events = deque(maxlen=500)
                    cls._instance._stats = {
                        'total': 0,
                        'blocked': 0,
                        'quarantined': 0,
                        'monitored': 0,
                        'allowed': 0,
                    }
                    cls._instance._lock = threading.Lock()
        return cls._instance

    def push(self, verdict: dict):
        with self._lock:
            self._events.appendleft(verdict)
            self._stats['total'] += 1
            action = verdict.get('action', 'allow')
            if action in self._stats:
                self._stats[action] += 1
            else:
                self._stats['allowed'] += 1

    def recent(self, limit: int = 50) -> list:
        with self._lock:
            return list(self._events)[:limit]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def clear(self):
        with self._lock:
            self._events.clear()
            for k in self._stats:
                self._stats[k] = 0
