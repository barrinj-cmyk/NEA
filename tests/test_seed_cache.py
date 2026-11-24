import sys

import seed_cache


def test_parse_service():
    assert seed_cache.parse_service("samba smbd:3.0.20") == ("samba smbd", "3.0.20")
    assert seed_cache.parse_service("withoutseparator") == ("", "withoutseparator")


def test_main_custom_services(monkeypatch, capsys):
    calls = []

    class FakeDB:
        def __init__(self, db, api_key=None):
            calls.append(("init", db, api_key))
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def get_vulnerabilities(self, product, version):
            calls.append(("lookup", product, version))
            return [("CVE-1", 3.0)]

    monkeypatch.setattr(seed_cache, "VulnDB", FakeDB)
    monkeypatch.setattr(sys, "argv", ["seed_cache.py", "apache httpd:2.4.57", "--db", "test.db", "--api-key", "key"])

    seed_cache.main()

    assert ("init", "test.db", "key") in calls
    assert ("lookup", "apache httpd", "2.4.57") in calls
    assert "apache httpd 2.4.57: 1 CVEs" in capsys.readouterr().out


def test_main_defaults(monkeypatch):
    lookups = []

    class FakeDB:
        def __init__(self, db, api_key=None):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def get_vulnerabilities(self, product, version):
            lookups.append((product, version))
            return []

    monkeypatch.setattr(seed_cache, "VulnDB", FakeDB)
    monkeypatch.setattr(sys, "argv", ["seed_cache.py"])
    seed_cache.main()

    assert lookups == seed_cache.DEFAULT_SERVICES
