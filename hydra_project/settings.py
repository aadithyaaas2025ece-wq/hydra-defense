"""
HYDRA DEFENSE SYSTEM - Django Settings
Multi-Agent AI Security Framework
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'hydra-defense-change-this-in-production-use-env-vars'

DEBUG = True  # Set False in production

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'channels',          # WebSocket support for live HUD
    'core',              # Main vulnerable app (for demo)
    'security_hud',      # Live security dashboard
]

# ─── HYDRA MIDDLEWARE STACK ────────────────────────────────────────────────
# Order matters! HydraGatekeeper runs FIRST, before anything else.
MIDDLEWARE = [
    'ai_agents.middleware.HydraGatekeeperMiddleware',   # 🛡️ THE HYDRA BRAIN
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'hydra_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'hydra_project.wsgi.application'
ASGI_APPLICATION = 'hydra_project.asgi.application'  # For Django Channels

# ─── DUAL DATABASE CONFIGURATION ──────────────────────────────────────────
# Production DB = real data
# Shadow DB     = poison data (fake records to trap hackers)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db_production.sqlite3',
    },
    'shadow': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db_shadow.sqlite3',
    }
}

# Database router — automatically picks which DB based on session threat score
DATABASE_ROUTERS = ['ai_agents.db_router.HydraDBRouter']

# ─── CHANNELS (WebSocket for live HUD) ────────────────────────────────────
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer"
        # For production: use Redis backend
        # "BACKEND": "channels_redis.core.RedisChannelLayer",
        # "CONFIG": {"hosts": [("127.0.0.1", 6379)]},
    }
}

# ─── HYDRA AI CONFIGURATION ───────────────────────────────────────────────
HYDRA_CONFIG = {
    # Ollama settings (local LLM)
    'OLLAMA_URL': os.environ.get('OLLAMA_URL', 'http://localhost:11434'),
    'OLLAMA_MODEL': os.environ.get('OLLAMA_MODEL', 'llama3.2:1b'),

    # Threat scoring thresholds
    'QUARANTINE_THRESHOLD': 0.7,    # Score above this → redirect to Shadow Realm
    'ALERT_THRESHOLD': 0.4,         # Score above this → log + monitor closely
    'BLOCK_THRESHOLD': 0.95,        # Score above this → hard block

    # Agent behavior
    'AGENT_TIMEOUT': 5,             # Seconds to wait for Ollama response
    'ENABLE_SHADOW_REALM': True,    # Set False to disable deception (just log)
    'ENABLE_HONEYPOT_DATA': True,   # Generate fake data for hackers

    # IPs that are never analyzed (your own dev machine)
    'WHITELIST_IPS': ['127.0.0.1', '::1'],

    # Paths that skip AI analysis (static files etc.)
    'SKIP_PATHS': ['/static/', '/favicon.ico', '/hud/ws/'],
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ─── LOGGING ──────────────────────────────────────────────────────────────
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'hydra': {
            'format': '[{asctime}] [{levelname}] HYDRA | {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'hydra',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs/hydra.log',
            'formatter': 'hydra',
        },
    },
    'loggers': {
        'hydra': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
