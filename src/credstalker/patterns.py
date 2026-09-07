"""Central registry of detection patterns.

Each entry in PATTERNS is a list of regex strings.
PATTERN_META holds human-readable severity + description for reporting.
"""

PATTERN_META = {
    "api_key": {
        "label": "API Key",
        "severity": "HIGH",
        "description": "Generic API keys / tokens (20+ char variants)",
    },
    "openai_key": {
        "label": "OpenAI Key",
        "severity": "CRITICAL",
        "description": "OpenAI sk- / sk-proj- keys",
    },
    "github_token": {
        "label": "GitHub Token",
        "severity": "CRITICAL",
        "description": "ghp_, gho_, ghu_, ghs_, ghr_ tokens",
    },
    "slack_token": {
        "label": "Slack Token",
        "severity": "CRITICAL",
        "description": "xox[baprs]- Slack tokens",
    },
    "google_api_key": {
        "label": "Google API Key",
        "severity": "HIGH",
        "description": "AIza... Google Cloud keys",
    },
    "stripe_key": {
        "label": "Stripe Key",
        "severity": "CRITICAL",
        "description": "sk_live_ / pk_live_ / rk_live_ keys",
    },
    "jwt": {
        "label": "JWT",
        "severity": "HIGH",
        "description": "JSON Web Tokens (eyJ...)",
    },
    "password": {
        "label": "Password",
        "severity": "CRITICAL",
        "description": "Hardcoded passwords / passwd / pwd assignments",
    },
    "username": {
        "label": "Username",
        "severity": "MEDIUM",
        "description": "Usernames, admin / root accounts",
    },
    "bearer_token": {
        "label": "Bearer Token",
        "severity": "HIGH",
        "description": "Bearer / auth tokens",
    },
    "database_url": {
        "label": "Database URL",
        "severity": "CRITICAL",
        "description": "MongoDB / Postgres / MySQL / Redis connection strings",
    },
    "private_key": {
        "label": "Private Key",
        "severity": "CRITICAL",
        "description": "RSA / EC / OpenSSH private key blocks",
    },
    "aws_key": {
        "label": "AWS Key",
        "severity": "CRITICAL",
        "description": "AKIA... Access Key IDs (+ secret pairs)",
    },
    "email": {
        "label": "Email",
        "severity": "LOW",
        "description": "Email addresses (PII / enumeration)",
    },
    "credit_card": {
        "label": "Credit Card",
        "severity": "HIGH",
        "description": "16-digit card numbers (masked formats)",
    },
    "webhook_url": {
        "label": "Webhook URL",
        "severity": "MEDIUM",
        "description": "Discord / Slack / generic webhook endpoints",
    },
    "obfuscated_string": {
        "label": "Obfuscated String",
        "severity": "MEDIUM",
        "description": "atob / btoa / decode / reverse tricks in JS",
    },
}

PATTERNS = {
    "api_key": [
        r'''(?i)(api[_-]?key|apikey|api_token)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?''',
        r'''(?i)(api[_-]?key)["']?\s*[:=]\s*["']?([^"'\s,}]+)["']?''',
    ],
    "openai_key": [
        r'''sk-(proj-)?[A-Za-z0-9\-_]{20,}''',
    ],
    "github_token": [
        r'''(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}''',
    ],
    "slack_token": [
        r'''xox[baprs]-[A-Za-z0-9\-_]{10,}''',
    ],
    "google_api_key": [
        r'''AIza[0-9A-Za-z\-_]{35}''',
    ],
    "stripe_key": [
        r'''(sk|pk|rk)_(live|test)_[A-Za-z0-9]{10,}''',
    ],
    "jwt": [
        r'''eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*''',
    ],
    "password": [
        r'''(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']?([^"'\s,}]{6,})["']?''',
        r'''(?i)(pass)["']?\s*[:=]\s*["']?([^"'\s,}]{6,})["']?''',
        r'''(?i)\.value\s*==\s*["']([^"']{6,})["']''',
    ],
    "username": [
        r'''(?i)(username|user|login|uname)["']?\s*[:=]\s*["']?([a-zA-Z0-9_\-\.@]{3,})["']?''',
        r'''(?i)(admin|root|user)["']?\s*[:=]\s*["']?([a-zA-Z0-9_]{3,})["']?''',
        r'''(?i)\.value\s*==\s*["']([a-zA-Z0-9_\-\.@]{3,})["']''',
    ],
    "bearer_token": [
        r'''(?i)bearer\s+[A-Za-z0-9\-_.~+/=]{20,}''',
        r'''(?i)(bearer|token|auth)["']?\s*[:=]\s*["']?([A-Za-z0-9\-_.]{20,})["']?''',
    ],
    "database_url": [
        r'''(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://[^\s"'<>]+''',
        r'''(?i)(database[_-]?url|db[_-]?url|mongo[_-]?uri|sql[_-]?url)["']?\s*[:=]\s*["']?([^"'\s,}]+)["']?''',
    ],
    "private_key": [
        r'''-----BEGIN[A-Z\s]*PRIVATE KEY-----[^-]+-----END[A-Z\s]*PRIVATE KEY-----''',
    ],
    "aws_key": [
        r'''\bAKIA[0-9A-Z]{16}\b''',
        r'''(?i)aws(.{0,20})?['"][0-9a-zA-Z/+=]{40}['"]''',
    ],
    "email": [
        r'''\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b''',
    ],
    "credit_card": [
        r'''\b\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}\b''',
    ],
    "webhook_url": [
        r'''https://discord(?:app)?\.com/api/webhooks/[^\s"'<>]+''',
        r'''https://hooks\.slack\.com/services/[^\s"'<>]+''',
        r'''(?i)(webhook|hook)[_-]?url["']?\s*[:=]\s*["']?([^"'\s,}]+)["']?''',
    ],
    "obfuscated_string": [
        r'''(?i)(RevereString|reverse|atob|btoa|decode|encode)\s*\(\s*["']([^"']+)["']\s*\)''',
    ],
}
