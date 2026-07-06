"""
╔══════════════════════════════════════════════════════════╗
║          HYDRA AI GATEKEEPER                             ║
║  Multi-Agent Security Intelligence Engine                ║
║                                                          ║
║  Agents:                                                 ║
║    🔍 Sentry      — Traffic pattern analysis             ║
║    💉 Venom       — SQL/XSS injection detection          ║
║    🤖 Hunter      — Bot & automation detection           ║
║    ⚖️  Strategist  — Final decision maker                ║
╚══════════════════════════════════════════════════════════╝
"""

import re
import json
import time
import hashlib
import logging
import requests
from datetime import datetime
from django.conf import settings

logger = logging.getLogger('hydra')

# ─── AGENT SYSTEM PROMPTS ─────────────────────────────────────────────────
# Each agent has a laser-focused job and MUST return JSON only.

SENTRY_PROMPT = """You are Sentry, a web traffic pattern analysis agent.
Analyze the HTTP request data and detect anomalies like:
- Unusually high frequency requests from same IP
- Requests at inhuman speed (< 100ms between requests)
- Scanning patterns (sequential paths: /admin, /admin1, /admin2...)
- Headers missing or fake (user-agent spoofing)
- Requests to sensitive paths (/.env, /wp-admin, /phpmyadmin)

You MUST respond with ONLY valid JSON, no other text:
{"score": 0.0, "reason": "brief reason", "agent": "Sentry", "indicators": ["list", "of", "flags"]}

Score 0.0 = completely safe. Score 1.0 = definite attacker. Be precise."""

VENOM_PROMPT = """You are Venom, a payload injection detection agent.
Analyze input data for malicious payloads including:
- SQL Injection: UNION SELECT, DROP TABLE, --, 1=1, OR 1=1, xp_cmdshell
- XSS: <script>, javascript:, onerror=, alert(, document.cookie
- Path Traversal: ../, ../../etc/passwd, %2e%2e
- Command Injection: ; ls, | cat, && rm, $(whoami)
- NoSQL Injection: $where, $gt, $ne operators in JSON
- LDAP/XML injection patterns

You MUST respond with ONLY valid JSON, no other text:
{"score": 0.0, "reason": "brief reason", "agent": "Venom", "attack_type": "none|sqli|xss|traversal|cmdi|nosqli", "payload_found": "exact suspicious string or null"}

Score 0.0 = no injection. Score 1.0 = clear injection attempt."""

HUNTER_PROMPT = """You are Hunter, a bot and automation detection agent.
Analyze behavioral signals to determine if traffic is from a bot/script:
- Mouse movement patterns (absent = likely bot)
- Timing between keystrokes (too perfect = bot)
- JavaScript execution capability
- Cookie handling patterns
- Accept-Language / Accept-Encoding headers consistency
- Referrer chain analysis
- Known bot user-agent strings

You MUST respond with ONLY valid JSON, no other text:
{"score": 0.0, "reason": "brief reason", "agent": "Hunter", "bot_type": "none|crawler|scraper|attack_bot|automated_tool"}

Score 0.0 = human. Score 1.0 = definitely automated."""

STRATEGIST_PROMPT = """You are the Strategist, the final decision-making agent of the Hydra Defense System.
You receive threat reports from three specialist agents (Sentry, Venom, Hunter) and make the final call.

Rules:
- If ANY agent scores > 0.9: action = "block" (certain attack)
- If combined weighted score > 0.7: action = "quarantine" (move to Shadow Realm)
- If combined weighted score > 0.4: action = "monitor" (watch closely)
- Otherwise: action = "allow"

Weights: Venom = 50%, Sentry = 30%, Hunter = 20%

You MUST respond with ONLY valid JSON, no other text:
{"final_score": 0.0, "action": "allow|monitor|quarantine|block", "reasoning": "brief explanation", "agent": "Strategist"}"""


class OllamaClient:
    """Thin wrapper around the Ollama HTTP API."""

    def __init__(self):
        cfg = settings.HYDRA_CONFIG
        self.base_url = cfg['OLLAMA_URL']
        self.model = cfg['OLLAMA_MODEL']
        self.timeout = cfg['AGENT_TIMEOUT']

    def ask(self, system_prompt: str, user_message: str) -> dict | None:
        """Send a prompt to Ollama and parse JSON response."""
        try:
            response = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.1,   # Low temp = consistent, deterministic
                        "num_predict": 200,   # We only need a short JSON response
                    }
                },
                timeout=self.timeout
            )
            if response.status_code == 200:
                content = response.json()['message']['content'].strip()
                # Strip any markdown code fences if model adds them
                content = re.sub(r'```json|```', '', content).strip()
                return json.loads(content)
        except requests.exceptions.ConnectionError:
            logger.warning("Ollama not reachable — running in RULE-BASED fallback mode")
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Ollama response parse error: {e}")
        return None


# ─── INDIVIDUAL AGENTS ────────────────────────────────────────────────────

class SentryAgent:
    """Watches for suspicious traffic patterns."""

    SENSITIVE_PATHS = [
        '/.env', '/wp-admin', '/phpmyadmin', '/admin.php',
        '/.git', '/config', '/backup', '/db', '/.htaccess',
        '/etc/passwd', '/proc/', '/shell', '/cmd',
    ]

    SCANNER_UA_PATTERNS = [
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
        'dirbuster', 'gobuster', 'hydra', 'medusa', 'burpsuite',
        'acunetix', 'nessus', 'openvas', 'metasploit',
    ]

    def __init__(self, ollama: OllamaClient):
        self.ollama = ollama

    def analyze(self, request_data: dict) -> dict:
        """Rule-based pre-filter + optional AI analysis."""
        score = 0.0
        indicators = []
        path = request_data.get('path', '')
        ua = request_data.get('user_agent', '').lower()

        # Rule-based checks (fast, no AI needed)
        for sp in self.SENSITIVE_PATHS:
            if sp in path:
                score = max(score, 0.8)
                indicators.append(f"sensitive_path:{sp}")

        for scanner in self.SCANNER_UA_PATTERNS:
            if scanner in ua:
                score = max(score, 0.95)
                indicators.append(f"scanner_ua:{scanner}")

        # Check for sequential scanning pattern in request history
        if request_data.get('request_count', 0) > 50:
            score = max(score, 0.6)
            indicators.append("high_frequency")

        # If rules already triggered, skip expensive AI call
        if score >= 0.8:
            return {"score": score, "reason": "Rule-based detection", "agent": "Sentry", "indicators": indicators}

        # AI analysis for ambiguous cases
        message = f"""
Path: {path}
Method: {request_data.get('method', 'GET')}
User-Agent: {request_data.get('user_agent', 'unknown')}
Referrer: {request_data.get('referrer', 'none')}
Request count from IP in last 5 min: {request_data.get('request_count', 1)}
Headers: {json.dumps(request_data.get('headers', {}))}
"""
        result = self.ollama.ask(SENTRY_PROMPT, message)
        if result:
            result['score'] = max(score, result.get('score', 0))
            result['indicators'] = indicators + result.get('indicators', [])
            return result

        return {"score": score, "reason": "fallback", "agent": "Sentry", "indicators": indicators}


class VenomAgent:
    """Detects injection payloads in inputs."""

    SQL_PATTERNS = [
        r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)",
        r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s+or\s+')",
        r"(?i)(xp_cmdshell|exec\s*\(|execute\s*\()",
        r"(--|#|/\*|\*/)",
        r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
        r"(?i)(information_schema|sys\.tables|pg_sleep)",
    ]

    XSS_PATTERNS = [
        r"(?i)(<script|</script>|javascript:|vbscript:)",
        r"(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=)",
        r"(?i)(alert\s*\(|confirm\s*\(|prompt\s*\()",
        r"(?i)(document\.cookie|document\.write|window\.location)",
        r"(?i)(eval\s*\(|setTimeout\s*\(|setInterval\s*\()",
    ]

    PATH_TRAVERSAL = [
        r"(\.\./|\.\.\\|%2e%2e)",
        r"(/etc/passwd|/etc/shadow|/proc/self)",
        r"(c:\\windows|c:/windows)",
    ]

    COMMAND_INJECTION = [
        r"(;\s*ls|;\s*cat|;\s*whoami|\|\s*ls|\|\s*cat)",
        r"(\$\(|`[^`]+`)",
        r"(&&\s*rm|&&\s*del|&&\s*format)",
    ]

    def __init__(self, ollama: OllamaClient):
        self.ollama = ollama
        self._compile_patterns()

    def _compile_patterns(self):
        self.sqli_re = [re.compile(p) for p in self.SQL_PATTERNS]
        self.xss_re = [re.compile(p) for p in self.XSS_PATTERNS]
        self.pt_re = [re.compile(p) for p in self.PATH_TRAVERSAL]
        self.ci_re = [re.compile(p) for p in self.COMMAND_INJECTION]

    def _scan(self, text: str) -> tuple[float, str, str]:
        """Returns (score, attack_type, matched_payload)."""
        for pat in self.sqli_re:
            m = pat.search(text)
            if m:
                return 0.9, "sqli", m.group(0)
        for pat in self.xss_re:
            m = pat.search(text)
            if m:
                return 0.9, "xss", m.group(0)
        for pat in self.pt_re:
            m = pat.search(text)
            if m:
                return 0.85, "traversal", m.group(0)
        for pat in self.ci_re:
            m = pat.search(text)
            if m:
                return 0.95, "cmdi", m.group(0)
        return 0.0, "none", "null"

    def analyze(self, request_data: dict) -> dict:
        """Scan all input fields for payloads."""
        all_inputs = []
        for key, val in request_data.get('post_data', {}).items():
            all_inputs.append(f"{key}={val}")
        for key, val in request_data.get('get_params', {}).items():
            all_inputs.append(f"{key}={val}")
        all_inputs.append(request_data.get('path', ''))

        combined = ' '.join(all_inputs)
        score, attack_type, payload = self._scan(combined)

        if score >= 0.85:
            # Clear hit — no need for AI
            return {
                "score": score,
                "reason": f"Pattern matched: {attack_type}",
                "agent": "Venom",
                "attack_type": attack_type,
                "payload_found": payload
            }

        if combined.strip():
            result = self.ollama.ask(VENOM_PROMPT, f"Analyze these inputs for malicious content:\n{combined[:500]}")
            if result:
                return result

        return {"score": 0.0, "reason": "clean", "agent": "Venom", "attack_type": "none", "payload_found": None}


class HunterAgent:
    """Detects bots and automated tools."""

    BOT_UA_STRINGS = [
        'python-requests', 'curl/', 'wget/', 'go-http-client',
        'libwww-perl', 'java/', 'okhttp', 'scrapy', 'phantomjs',
        'headlesschrome', 'selenium', 'playwright', 'puppeteer',
    ]

    def __init__(self, ollama: OllamaClient):
        self.ollama = ollama

    def analyze(self, request_data: dict) -> dict:
        ua = request_data.get('user_agent', '').lower()
        score = 0.0
        bot_type = "none"

        # Check for known bot UAs
        for bot in self.BOT_UA_STRINGS:
            if bot in ua:
                score = 0.95
                bot_type = "automated_tool"
                break

        # Empty or missing UA is suspicious
        if not ua or ua == '-':
            score = max(score, 0.7)
            bot_type = "suspicious"

        # Missing Accept-Language header (browsers always send this)
        headers = request_data.get('headers', {})
        if not headers.get('Accept-Language') and score < 0.7:
            score = max(score, 0.5)
            bot_type = "likely_bot"

        if score >= 0.7:
            return {"score": score, "reason": f"Bot indicator: {bot_type}", "agent": "Hunter", "bot_type": bot_type}

        # AI for ambiguous cases
        message = f"""
User-Agent: {ua}
Accept-Language: {headers.get('Accept-Language', 'MISSING')}
Accept-Encoding: {headers.get('Accept-Encoding', 'MISSING')}
Connection: {headers.get('Connection', 'MISSING')}
JS-Fingerprint-Available: {request_data.get('js_fingerprint', False)}
Mouse-Movement-Detected: {request_data.get('mouse_moved', False)}
"""
        result = self.ollama.ask(HUNTER_PROMPT, message)
        if result:
            return result

        return {"score": score, "reason": "no bot indicators", "agent": "Hunter", "bot_type": "none"}


class StrategistAgent:
    """Combines all agent reports into final decision."""

    def __init__(self, ollama: OllamaClient):
        self.ollama = ollama
        cfg = settings.HYDRA_CONFIG
        self.quarantine_threshold = cfg['QUARANTINE_THRESHOLD']
        self.block_threshold = cfg['BLOCK_THRESHOLD']
        self.alert_threshold = cfg['ALERT_THRESHOLD']

    def decide(self, sentry: dict, venom: dict, hunter: dict) -> dict:
        """Weighted scoring + AI final review."""
        s_score = sentry.get('score', 0) * 0.30
        v_score = venom.get('score', 0) * 0.50
        h_score = hunter.get('score', 0) * 0.20
        combined = s_score + v_score + h_score

        # Rule-based final decision
        if combined >= self.block_threshold or max(sentry.get('score', 0), venom.get('score', 0), hunter.get('score', 0)) >= 0.95:
            action = "block"
        elif combined >= self.quarantine_threshold:
            action = "quarantine"
        elif combined >= self.alert_threshold:
            action = "monitor"
        else:
            action = "allow"

        # Quick AI sanity check for borderline cases
        if 0.35 < combined < 0.75:
            message = f"""Agent reports:
Sentry: {json.dumps(sentry)}
Venom: {json.dumps(venom)}
Hunter: {json.dumps(hunter)}
Calculated weighted score: {combined:.2f}
Make the final decision."""
            result = self.ollama.ask(STRATEGIST_PROMPT, message)
            if result:
                return result

        return {
            "final_score": round(combined, 3),
            "action": action,
            "reasoning": f"Weighted: Sentry={sentry.get('score',0):.2f} Venom={venom.get('score',0):.2f} Hunter={hunter.get('score',0):.2f}",
            "agent": "Strategist"
        }


# ─── MAIN GATEKEEPER ORCHESTRATOR ─────────────────────────────────────────

class HydraGatekeeper:
    """
    The central Hydra brain. Orchestrates all agents and returns a verdict.
    Usage:
        gatekeeper = HydraGatekeeper()
        verdict = gatekeeper.evaluate(request_data)
    """

    def __init__(self):
        self.ollama = OllamaClient()
        self.sentry = SentryAgent(self.ollama)
        self.venom = VenomAgent(self.ollama)
        self.hunter = HunterAgent(self.ollama)
        self.strategist = StrategistAgent(self.ollama)

    def evaluate(self, request_data: dict) -> dict:
        """
        Full multi-agent evaluation pipeline.
        Returns: {action, final_score, agents: {sentry, venom, hunter, strategist}}
        """
        start = time.time()
        logger.info(f"[Hydra] Evaluating {request_data.get('path')} from {request_data.get('ip')}")

        # Run agents (in production, run these in parallel with ThreadPoolExecutor)
        sentry_result = self.sentry.analyze(request_data)
        venom_result = self.venom.analyze(request_data)
        hunter_result = self.hunter.analyze(request_data)

        # Log agent findings
        for agent_result in [sentry_result, venom_result, hunter_result]:
            score = agent_result.get('score', 0)
            agent_name = agent_result.get('agent', 'Unknown')
            reason = agent_result.get('reason', '')
            if score > 0.3:
                logger.warning(f"[{agent_name}] score={score:.2f} | {reason}")
            else:
                logger.debug(f"[{agent_name}] score={score:.2f} | {reason}")

        # Strategist makes final call
        strategy = self.strategist.decide(sentry_result, venom_result, hunter_result)

        elapsed = time.time() - start
        action = strategy.get('action', 'allow')
        final_score = strategy.get('final_score', 0)

        logger.info(f"[Strategist] Decision: {action.upper()} | Score: {final_score:.3f} | Time: {elapsed:.2f}s")

        return {
            "action": action,
            "final_score": final_score,
            "elapsed_ms": round(elapsed * 1000),
            "timestamp": datetime.utcnow().isoformat(),
            "ip": request_data.get('ip'),
            "path": request_data.get('path'),
            "agents": {
                "sentry": sentry_result,
                "venom": venom_result,
                "hunter": hunter_result,
                "strategist": strategy,
            }
        }
