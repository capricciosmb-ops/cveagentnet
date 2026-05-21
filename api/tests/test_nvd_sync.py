from __future__ import annotations

from api.services.nvd_sync import NVDSyncService


def test_parse_reference_urls_handles_nvd_2_0_schema():
    # Real-shape NVD 2.0 response: cve.references is a flat list, not the
    # legacy 1.0 ``{"referenceData": [...]}`` wrapper.
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "references": [
                        {"url": "https://example.com/advisory", "source": "ex", "tags": ["Vendor Advisory"]},
                        {"url": "https://example.org/patch", "source": "ex"},
                    ],
                }
            }
        ]
    }
    assert NVDSyncService.parse_reference_urls(payload) == [
        "https://example.com/advisory",
        "https://example.org/patch",
    ]


def test_parse_reference_urls_returns_empty_for_missing_or_malformed():
    assert NVDSyncService.parse_reference_urls({}) == []
    assert NVDSyncService.parse_reference_urls({"vulnerabilities": []}) == []
    assert NVDSyncService.parse_reference_urls(
        {"vulnerabilities": [{"cve": {"references": None}}]}
    ) == []
    # A stray non-dict entry must not crash the parser.
    assert NVDSyncService.parse_reference_urls(
        {"vulnerabilities": [{"cve": {"references": ["bad", {"url": "https://ok.example/x"}]}}]}
    ) == ["https://ok.example/x"]
