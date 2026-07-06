# 🐍 HYDRA DEFENSE SYSTEM
### Multi-Agent AI Security Framework for Django

A production-grade autonomous website protection system featuring:
- **4 specialized AI agents** running in a collaborative "hive mind"
- **Shadow Realm deception** — attackers get routed to a fake site without knowing
- **Live Security HUD** — real-time WebSocket dashboard showing agent decisions
- **AI Honeypot data** — fake databases that waste attacker's time
- **Local LLM integration** via Ollama (no API costs, runs on your machine)

---

## Architecture

```
HTTP Request
    │
    ▼
┌─────────────────────────────────────────┐
│     HydraGatekeeperMiddleware           │
│  (runs before EVERY view)               │
└──────────┬──────────────────────────────┘
           │
    ┌──────▼──────────────────────────────┐
    │         AI Agent Pipeline           │
    │  ┌────────┐ ┌────────┐ ┌────────┐  │
    │  │ Sentry │ │ Venom  │ │ Hunter │  │
    │  │Traffic │ │ SQLi/  │ │  Bot   │  │
    │  │Patterns│ │  XSS   │ │Detect. │  │
    │  └───┬────┘ └───┬────┘ └───┬────┘  │
    │      └──────────┼──────────┘        │
    │            ┌────▼─────┐             │
    │            │Strategist│             │
    │            │ (judge)  │             │
    │            └────┬─────┘             │
    └─────────────────┼───────────────────┘
                      │
           ┌──────────▼──────────┐
           │  Decision:          │
           │  ALLOW  → Real DB   │
           │  MONITOR→ Real DB + │
           │           Log       │
           │  QUARANTINE→Shadow  │
           │           DB (fake) │
           │  BLOCK  → 403       │
           └─────────────────────┘
```

---

## Quick Start

### 1. Prerequisites

```bash
# Python 3.10+
python --version

# Install Ollama (for local AI)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the model (1B params, fast, ~800MB)
ollama pull llama3.2:1b

# Start Ollama server (keep this running)
ollama serve
```

### 2. Install & Configure

```bash
cd hydra_defense

# Create virtual environment
python -m venv venv
source venv/bin/activate       # Linux/Mac
# venv\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Initialize Databases

```bash
# Create both databases (real + shadow)
python manage.py migrate
python manage.py migrate --database=shadow

# Seed shadow DB with poison data
python manage.py seed_shadow_db --count=100

# Seed real DB with sample data (optional)
python manage.py seed_shadow_db --real

# Create admin user for Django admin
python manage.py createsuperuser
```

### 4. Run the Server

```bash
# Use Daphne (ASGI server with WebSocket support)
daphne -p 8000 hydra_project.asgi:application

# OR use Django's dev server (WebSocket won't work, but HTTP protection will)
python manage.py runserver
```

### 5. Open the HUD

Go to `http://localhost:8000/hud/` — this is your live Security HUD.

Open `http://localhost:8000/` in another tab and try some attacks!

---

## Testing the System

### Test SQL Injection Detection
```bash
# This should be QUARANTINED
curl "http://localhost:8000/search/?q=admin'%20UNION%20SELECT%20*%20FROM%20users--"

# Using sqlmap (will definitely trigger Hunter + Sentry)
sqlmap -u "http://localhost:8000/search/?q=test" --batch
```

### Test XSS Detection
```bash
curl "http://localhost:8000/search/?q=<script>alert('xss')</script>"
```

### Test Bot Detection
```bash
# python-requests is in the bot UA list
python -c "import requests; r = requests.get('http://localhost:8000/')"
```

### Test Path Scanning
```bash
# Sequential path scanning triggers Sentry
for path in /admin /.env /wp-admin /phpmyadmin /config /.git; do
  curl -s "http://localhost:8000$path" > /dev/null
done
```

---

## Configuration

All settings are in `hydra_project/settings.py` under `HYDRA_CONFIG`:

```python
HYDRA_CONFIG = {
    'OLLAMA_URL': 'http://localhost:11434',   # Ollama server
    'OLLAMA_MODEL': 'llama3.2:1b',            # Model to use
    'QUARANTINE_THRESHOLD': 0.7,              # When to redirect to Shadow Realm
    'BLOCK_THRESHOLD': 0.95,                  # When to hard block
    'ALERT_THRESHOLD': 0.4,                   # When to log + monitor
    'ENABLE_SHADOW_REALM': True,              # Toggle deception on/off
    'WHITELIST_IPS': ['127.0.0.1', '::1'],   # Never analyzed
}
```

---

## Running Without Ollama (Rule-Based Mode)

The system works without Ollama! If Ollama isn't running, each agent
automatically falls back to pure rule-based detection:
- Venom: regex pattern matching for SQLi/XSS/traversal
- Sentry: known scanner UA strings and sensitive path detection
- Hunter: UA string analysis for known bot libraries

You'll see this log message: `Ollama not reachable — running in RULE-BASED fallback mode`

---

## Production Deployment Notes

1. **Change `SECRET_KEY`** — never use the default in production
2. **Set `DEBUG = False`**
3. **Use Redis** for Channel Layers instead of InMemoryChannelLayer
4. **Use PostgreSQL** for both databases (SQLite not recommended in production)
5. **Run behind Nginx** as a reverse proxy in front of Daphne
6. **Use environment variables** for all secrets (python-dotenv is included)

---

## File Structure

```
hydra_defense/
├── hydra_project/          # Django project config
│   ├── settings.py         # Main config + HYDRA_CONFIG
│   ├── urls.py             # URL routing
│   └── asgi.py             # ASGI + WebSocket setup
│
├── ai_agents/              # 🧠 THE BRAIN
│   ├── gatekeeper.py       # 4 AI agents + orchestrator
│   ├── middleware.py       # Django middleware interceptor
│   ├── db_router.py        # Shadow/Real DB router
│   ├── event_store.py      # In-memory event ring buffer
│   └── honeypot.py         # Fake data generator
│
├── core/                   # Demo target web app
│   ├── models.py           # UserProfile model
│   ├── views.py            # Home, Search, Login, Shadow views
│   └── templates/core/     # HTML templates
│
├── security_hud/           # 📊 Live dashboard
│   ├── consumers.py        # WebSocket consumer
│   ├── views.py            # HUD view
│   └── templates/hud/      # Dashboard HTML (the cool UI)
│
├── logs/                   # Hydra log output
├── requirements.txt
└── README.md
```

---

## How the Shadow Realm Works

```
Attacker sends SQL injection payload
         ↓
Venom agent detects it (score: 0.9)
         ↓
Strategist decides: QUARANTINE
         ↓
Session var 'in_shadow_realm' = True
         ↓
DB Router sends ALL queries → Shadow DB
         ↓
Attacker sees realistic fake data
(200 fake users, fake transactions, fake config)
         ↓
They think they've breached the system!
Meanwhile, you watch their every move on the HUD.
```

---

Built with ❤️ using Django + Channels + Ollama
