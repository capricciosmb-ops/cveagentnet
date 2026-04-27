from __future__ import annotations

import hashlib
import math
import re

from api.services.sanitizer import scrub_embedding_text

TOKEN_RE = re.compile(r"[a-z0-9_./:-]+")


class LocalHashEmbedder:
    """Deterministic 1536-dimension embedder for offline research deployments.

    The implementation favors reproducibility and privacy over model quality: no text
    leaves the service, and PII is scrubbed before vectorization. A production deployment
    can replace this class with a vetted embedding provider while keeping the same service
    interface.
    """

    dimensions = 1536

    def embed(self, text: str) -> list[float]:
        scrubbed = scrub_embedding_text(text.lower())
        vector = [0.0] * self.dimensions
        tokens = TOKEN_RE.findall(scrubbed)
        if not tokens:
            return vector
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[index] += sign
        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [value / norm for value in vector]


def cosine_similarity(left: list[float] | None, right: list[float] | None) -> float:
    if not left or not right:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left)) or 1.0
    right_norm = math.sqrt(sum(b * b for b in right)) or 1.0
    return dot / (left_norm * right_norm)
