"""Core crawler + detector."""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .patterns import PATTERNS

# Silence InsecureRequestWarning when verify=False (lab / bug-bounty default)
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0 Safari/537.36 CredStalker/2.0"
)


@dataclass
class Finding:
    url: str
    type: str
    match: str
    source: str

    def to_dict(self) -> dict:
        return asdict(self)


class CredentialScanner:
    """Crawl a single scope and match content against PATTERNS."""

    def __init__(
        self,
        base_url: str,
        max_depth: int = 3,
        verbose: bool = False,
        timeout: int = 8,
        max_urls: int = 200,
        delay: float = 0.0,
        user_agent: str = DEFAULT_UA,
        include_subdomains: bool = False,
        silent: bool = False,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            base_url = "http://" + base_url
        self.base_url = base_url.rstrip("/")
        self.max_depth = max_depth
        self.verbose = verbose and not silent
        self.timeout = timeout
        self.max_urls = max_urls
        self.delay = delay
        self.silent = silent

        parsed = urlparse(self.base_url)
        self.domain = parsed.netloc
        self.base_host = parsed.hostname or ""
        self.include_subdomains = include_subdomains

        self.visited_urls: Set[str] = set()
        self.findings: Dict[str, List[dict]] = defaultdict(list)
        self._seen_matches: Set[str] = set()

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

        # Pre-compile for speed
        self._compiled = {
            kind: [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in plist]
            for kind, plist in PATTERNS.items()
        }

    # -- public API -----------------------------------------------------
    def scan(self) -> Dict[str, List[dict]]:
        if not self.silent:
            print(f"\n{'=' * 60}")
            print(f"🔍 Starting scan on: {self.base_url}")
            print(f"   depth={self.max_depth}  max_urls={self.max_urls}  timeout={self.timeout}s")
            print(f"{'=' * 60}\n")
        self._crawl_url(self.base_url, depth=0)
        return dict(self.findings)

    @property
    def total_findings(self) -> int:
        return sum(len(v) for v in self.findings.values())

    def export_json(self, filename: str = "findings.json") -> str:
        import json

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(dict(self.findings), f, indent=2)
        if not self.silent:
            print(f"  Results exported to {filename}")
        return filename

    # -- crawling --------------------------------------------------------
    def _in_scope(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
            if self.include_subdomains:
                return host == self.base_host or host.endswith("." + self.base_host)
            return urlparse(url).netloc == self.domain
        except Exception:
            return False

    def _crawl_url(self, url: str, depth: int) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return
        if len(self.visited_urls) >= self.max_urls:
            if self.verbose:
                print(f"[!] max-urls limit reached ({self.max_urls}), stopping.")
            return

        # strip fragments, skip non-http(s)
        url = url.split("#")[0]
        if not url.startswith(("http://", "https://")):
            return

        self.visited_urls.add(url)
        if self.verbose:
            print(f"[*] Crawling ({depth}): {url}")

        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code != 200:
                if self.verbose:
                    print(f"[!] {resp.status_code} — {url}")
                return
            content_type = resp.headers.get("Content-Type", "")
            if "text" not in content_type and "html" not in content_type and "javascript" not in content_type:
                # still scan small bodies, skip binaries
                if len(resp.text) > 2_000_000:
                    return

            text = resp.text
            self._analyze_content(text, url)

            if self.delay:
                time.sleep(self.delay)

            if depth < self.max_depth:
                soup = BeautifulSoup(text, "html.parser")

                # 1) fetch inline-linked JS files (biggest credential surface)
                for tag in soup.find_all("script", src=True):
                    js_url = urljoin(url, tag["src"]).split("#")[0]
                    if js_url not in self.visited_urls and self._in_scope(js_url):
                        self._fetch_and_scan_asset(js_url)

                # 2) follow anchor links
                for link in soup.find_all("a", href=True):
                    href: str = link["href"]
                    if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                        continue
                    abs_url = urljoin(url, href).split("#")[0]
                    if self._in_scope(abs_url):
                        self._crawl_url(abs_url, depth + 1)

        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[!] Error accessing {url}: {e}")

    def _fetch_and_scan_asset(self, url: str) -> None:
        """Fetch a JS / asset URL and scan it without expanding crawl depth."""
        if len(self.visited_urls) >= self.max_urls or url in self.visited_urls:
            return
        self.visited_urls.add(url)
        if self.verbose:
            print(f"[*] Asset: {url}")
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and len(resp.text) < 5_000_000:
                self._analyze_content(resp.text, url)
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"[!] Error fetching asset {url}: {e}")

    # -- detection -------------------------------------------------------
    def _analyze_content(self, content: str, url: str) -> None:
        js_blocks = re.findall(
            r"<script[^>]*>([^<]*)</script>", content, re.IGNORECASE | re.DOTALL
        )
        for js in js_blocks:
            if js.strip():
                self._check_patterns(js, url, "JavaScript")

        for comment in re.findall(r"<!--(.*?)-->", content, re.DOTALL):
            self._check_patterns(comment, url, "HTML Comment")

        self._check_patterns(content, url, "HTML")

    def _check_patterns(self, text: str, url: str, source: str) -> None:
        for kind, compiled in self._compiled.items():
            for rx in compiled:
                for m in rx.finditer(text):
                    raw = m.group(0).strip()
                    if len(raw) > 500:
                        raw = raw[:500] + "…"
                    dedup_key = f"{kind}|{raw[:200]}|{url}"
                    if dedup_key in self._seen_matches:
                        continue
                    self._seen_matches.add(dedup_key)
                    finding = Finding(url=url, type=kind, match=raw, source=source)
                    self.findings[kind].append(finding.to_dict())
                    if self.verbose and not self.silent:
                        print(f"[+] Found {kind} in {source}: {raw[:80]}")
