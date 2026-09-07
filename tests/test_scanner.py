"""Scanner unit tests with mocked HTTP."""

from credstalker.scanner import CredentialScanner


class FakeResponse:
    status_code = 200
    headers = {"Content-Type": "text/html"}
    text = """
    <html>
    <!-- admin password = "SuperSecret123" -->
    <script>const api_key = "sk_live_1234567890abcdefXY";</script>
    <a href="/about">about</a>
    <a href="https://evil.com/x">evil</a>
    </html>
    """


class FakeSession:
    def __init__(self):
        self.headers = {}

    def get(self, url, timeout=8, verify=False):
        return FakeResponse()


def test_scan_finds_password_and_key_and_stays_in_scope(monkeypatch):
    import credstalker.scanner as mod

    # patch Session globally for this test
    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession())

    s = CredentialScanner("http://example.com", max_depth=1, max_urls=10, silent=True)
    findings = s.scan()
    assert "password" in findings
    assert "api_key" in findings
    # out-of-scope link must never be visited
    assert all("evil.com" not in u for u in s.visited_urls)


def test_dedup_and_export(tmp_path, monkeypatch):
    import credstalker.scanner as mod

    monkeypatch.setattr(mod.requests, "Session", lambda: FakeSession())
    s = CredentialScanner("http://example.com", max_depth=0, silent=True)
    s.scan()
    first_total = s.total_findings
    # re-scan same content → dedup keeps count stable per-URL
    s.visited_urls.clear()
    s.scan()
    assert s.total_findings == first_total  # same URL skipped via visited set

    out = tmp_path / "out.json"
    s.export_json(str(out))
    assert out.exists()
