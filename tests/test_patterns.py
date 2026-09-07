"""Pattern smoke tests — every category must fire on a canonical sample."""

import re

from credstalker.patterns import PATTERNS

SAMPLES = {
    "api_key": 'api_key = "sk_live_1234567890abcdefXY"',
    "openai_key": "sk-proj-1234567890abcdef1234567890abcdef",
    "github_token": "ghp_1234567890abcdef1234567890abcdef1234",
    "slack_token": "xoxb-123456789012-123456789012-abcdef123456",
    "google_api_key": "AIzaSyD1234567890abcdef1234567890abcd12",
    "stripe_key": "sk_live_1234567890abcdef1234",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "password": 'password = "SecurePass123"',
    "username": 'username = "admin_user"',
    "bearer_token": "Authorization: Bearer abcdef1234567890XYZ._-token",
    "database_url": "mongodb://admin:secret123@localhost:27017/mydb",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIBPAIBAA==\n-----END RSA PRIVATE KEY-----",
    "aws_key": "AKIAIOSFODNN7EXAMPLE",
    "email": "contact@example.com",
    "credit_card": "4111 1111 1111 1111",
    "webhook_url": "https://discord.com/api/webhooks/123/abc-def_ghi",
    "obfuscated_string": 'atob("c2VjcmV0LXRva2Vu")',
}


def test_all_patterns_match_samples():
    missing = []
    for kind, sample in SAMPLES.items():
        compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in PATTERNS[kind]]
        if not any(rx.search(sample) for rx in compiled):
            missing.append(kind)
    assert not missing, f"patterns failed to match: {missing}"


def test_meta_covers_all_patterns():
    from credstalker.patterns import PATTERN_META

    assert set(PATTERN_META) == set(PATTERNS)
