from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

SCRIPT_BLOCK_RE = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
EVENT_HANDLER_RE = re.compile(r"\son[a-z]+\s*=\s*(['\"]).*?\1", re.IGNORECASE | re.DOTALL)
CREDENTIAL_URL_RE = re.compile(r"\bhttps?://[^/\s:@]+:[^/\s@]+@[^/\s]+", re.IGNORECASE)
SHELLCODE_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CREDENTIAL_RE = re.compile(r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret)\s*[:=]\s*['\"]?[^'\"\s]+")


def sanitize_payload_sample(payload: str | None) -> str | None:
    if payload is None:
        return None
    cleaned = SCRIPT_BLOCK_RE.sub("[removed script block]", payload)
    cleaned = EVENT_HANDLER_RE.sub(" [removed event handler]", cleaned)
    cleaned = CREDENTIAL_URL_RE.sub("https://[removed-credentials]@[redacted-host]", cleaned)
    cleaned = SHELLCODE_HEX_RE.sub("[removed shellcode-like bytes]", cleaned)
    cleaned = BASE64_BLOB_RE.sub("[removed large encoded blob]", cleaned)
    return cleaned[:5000]


def scrub_embedding_text(text: str) -> str:
    scrubbed = IPV4_RE.sub("[ip-address]", text)
    scrubbed = IPV6_RE.sub("[ipv6-address]", scrubbed)
    scrubbed = EMAIL_RE.sub("[email-address]", scrubbed)
    scrubbed = CREDENTIAL_RE.sub(lambda match: f"{match.group(1)}=[credential]", scrubbed)
    if scrubbed != text:
        logger.info("PII/credential scrubber modified text before embedding generation")
    return scrubbed

