"""
HYDRA DB ROUTER
Dynamically routes database queries.

Real users  → production database (real data)
Quarantined → shadow database (poison/fake data)

The router reads a thread-local variable set by the middleware.
"""

import threading
import logging

logger = logging.getLogger('hydra')

# Thread-local storage to pass DB choice from middleware to ORM layer
_thread_local = threading.local()


def set_shadow_realm(enabled: bool):
    """Called by middleware to mark this thread as shadow-routed."""
    _thread_local.shadow_realm = enabled


def in_shadow_realm() -> bool:
    return getattr(_thread_local, 'shadow_realm', False)


class HydraDBRouter:
    """
    Routes queries to 'shadow' DB for quarantined sessions,
    'default' for everyone else.
    """

    # These app labels always use the default DB regardless of threat score
    # (auth/admin must always be real for the system to function)
    ALWAYS_REAL = {'auth', 'admin', 'contenttypes', 'sessions', 'security_hud'}

    def db_for_read(self, model, **hints):
        if model._meta.app_label in self.ALWAYS_REAL:
            return 'default'
        if in_shadow_realm():
            logger.debug(f"[HydraRouter] 🕳️ Read → SHADOW DB ({model.__name__})")
            return 'shadow'
        return 'default'

    def db_for_write(self, model, **hints):
        if model._meta.app_label in self.ALWAYS_REAL:
            return 'default'
        if in_shadow_realm():
            logger.debug(f"[HydraRouter] 🕳️ Write → SHADOW DB ({model.__name__})")
            return 'shadow'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        # Allow all relations within the same DB
        return True

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # Run migrations on both DBs for app models
        if app_label in self.ALWAYS_REAL:
            return db == 'default'
        return True  # Migrate to both DBs
