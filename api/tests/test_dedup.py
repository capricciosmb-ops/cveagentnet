from __future__ import annotations

from api.services.dedup import DeduplicationService


def test_fingerprint_is_normalized_and_tool_order_independent():
    service = DeduplicationService()
    left = service.compute_fingerprint(" Parser RCE ", "research-lab", ["nuclei", "openclaw"])
    right = service.compute_fingerprint("parser rce", "research-lab", ["openclaw", "nuclei"])
    assert left == right
    assert len(left) == 64

