import json
import sqlite3

import pytest

from vuln_db import (
    VulnDB,
    normalise_product,
    normalise_version,
)


@pytest.mark.parametrize("value, expected", [
    ("  Apache   HTTPD ", "apache httpd"),
    (None, ""),
    (123, ""),
])
def test_normalise_product(value, expected):
    assert normalise_product(value) == expected


@pytest.mark.parametrize("value, expected", [
    ("Apache 2.4.57 release", "2.4"),
    ("3.0.20", "3.0"),
    (None, None),
    ("unknown", None),
])
def test_normalise_version(value, expected):
    assert normalise_version(value) == expected


def test_cache_store_get_and_context_manager(tmp_path):
    db_path = tmp_path / "cache.db"
    with VulnDB(db_path, offline=True) as db:
        assert db.get_cached("Apache HTTPD", "2.4.57") is None
        db.store("Apache HTTPD", "2.4.57", [
            ("CVE-2024-1", 3.9, 9.8, "Apache vulnerability"),
            ("CVE-2024-2", 2.8),
        ])
        assert db.get_cached("  APACHE   httpd ", "2.4.57") == [
            ("CVE-2024-1", 3.9),
            ("CVE-2024-2", 2.8),
        ]


def test_store_normalises_keys_and_rejects_invalid_values(tmp_path):
    db = VulnDB(tmp_path / "cache.db", offline=True)
    try:
        db.store("  Samba   SMBd ", "3.0.20", [("CVE-1", 3.0)])
        assert db.get_cached("samba smbd", "3.0") == [("CVE-1", 3.0)]
        with pytest.raises(ValueError, match="cannot store"):
            db.store("", "3.0", [])
        with pytest.raises(ValueError, match="cannot store"):
            db.store("apache", "unknown", [])
    finally:
        db.close()


def test_empty_cache_result_is_distinguishable_from_missing(tmp_path):
    db = VulnDB(tmp_path / "cache.db", offline=True)
    try:
        db.store("nginx", "1.24", [])
        assert db.get_cached("nginx", "1.24") == []
        assert db.get_cached("nginx", "1.25") is None
    finally:
        db.close()


def test_offline_lookup_never_calls_network(tmp_path, monkeypatch):
    db = VulnDB(tmp_path / "cache.db", offline=True)
    try:
        def unexpected(*args, **kwargs):
            raise AssertionError("network lookup should not occur")

        monkeypatch.setattr(db, "_fetch_nvd", unexpected)
        assert db.get_vulnerabilities("apache", "2.4.57") == []
        assert db.get_cached("apache", "2.4.57") is None
    finally:
        db.close()


def test_cached_lookup_does_not_call_network(tmp_path, monkeypatch):
    db = VulnDB(tmp_path / "cache.db")
    try:
        db.store("apache", "2.4", [("CVE-CACHED", 3.2)])
        monkeypatch.setattr(db, "_fetch_nvd", lambda *args: pytest.fail("network lookup occurred"))
        assert db.get_vulnerabilities("Apache", "2.4.99") == [("CVE-CACHED", 3.2)]
    finally:
        db.close()


def test_lookup_network_failure_warns_and_is_not_cached(tmp_path, monkeypatch, capsys):
    db = VulnDB(tmp_path / "cache.db")
    try:
        monkeypatch.setattr(db, "_fetch_nvd", lambda *args: (_ for _ in()).throw(OSError("offline")))
        assert db.get_vulnerabilities("apache", "2.4") == []
        assert "NVD lookup failed" in capsys.readouterr().err
        assert db.get_cached("apache", "2.4") is None
    finally:
        db.close()


def test_parse_nvd_filters_and_normalises_results():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "metrics": {"cvssMetricV31": [{
                        "exploitabilityScore": 3.9,
                        "cvssData": {"baseScore": 9.8},
                    }]},
                    "descriptions": [{"lang": "en", "value": "Apache HTTP Server 2.4 vulnerability"}],
                    "configurations": [],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-NOMATCH",
                    "metrics": {"cvssMetricV30": [{
                        "exploitabilityScore": 1.0,
                        "cvssData": {"baseScore": 5.0},
                    }]},
                    "descriptions": [{"lang": "en", "value": "Nginx 1.24 vulnerability"}],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-NOV3",
                    "descriptions": [{"lang": "en", "value": "Apache 2.4 vulnerability"}],
                }
            },
        ]
    }

    results = VulnDB._parse_nvd(payload, "apache httpd", "apache http server", "2.4")
    assert results == [("CVE-2024-1234", 3.9, 9.8, "Apache HTTP Server 2.4 vulnerability")]


def test_extract_v3_scores_falls_back_to_v30():
    cve = {"metrics": {"cvssMetricV30": [{
        "exploitabilityScore": 2.1,
        "cvssData": {"baseScore": 7.5},
    }]}}
    assert VulnDB._extract_v3_scores(cve) == (2.1, 7.5)
    assert VulnDB._extract_v3_scores({}) is None


def test_english_description_and_mentions():
    cve = {
        "descriptions": [
            {"lang": "fr", "value": "description française"},
            {"lang": "en", "value": "Example Server 1.2 vulnerability"},
        ],
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:/a:vendor:server:1.2"}]}]}],
    }
    assert VulnDB._english(cve) == "Example Server 1.2 vulnerability"
    assert VulnDB._mentions(cve, {"example server"}, "1.2")
    assert not VulnDB._mentions(cve, {"apache"}, "1.2")


def test_fetch_nvd_builds_alias_query_and_headers(tmp_path, monkeypatch):
    db = VulnDB(tmp_path / "cache.db", api_key="secret")
    captured = {}

    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["api_key"] = request.get_header("Apikey")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("json.load", lambda response: {"vulnerabilities": []})
    monkeypatch.setattr("time.sleep", lambda seconds: None)

    try:
        assert db._fetch_nvd("apache httpd", "2.4") == []
        assert "keywordSearch=apache+http+server+2.4" in captured["url"]
        assert captured["api_key"] == "secret"
        assert captured["timeout"] == 10
    finally:
        db.close()
