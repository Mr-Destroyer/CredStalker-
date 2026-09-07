"""CredStalker — Credential & Sensitive Data Scanner."""

__version__ = "2.0.0"
__author__ = "Mr-Destroyer"
__license__ = "MIT"

from .scanner import CredentialScanner
from .patterns import PATTERNS, PATTERN_META

__all__ = ["CredentialScanner", "PATTERNS", "PATTERN_META", "__version__"]
