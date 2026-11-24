import pytest

import scanner


class FakeHost:
    def __init__(self, ip, state="up", protocols=None):
        self.ip = ip
        self._state = state
        self._protocols = protocols or {}

    def state(self):
        return self._state

    def all_protocols(self):
        return list(self._protocols)

    def __getitem__(self, protocol):
        return self._protocols[protocol]


class FakePortScanner:
    def __init__(self, hosts):
        self._hosts = hosts

    def scan(self, **kwargs):
        return None

    def all_hosts(self):
        return list(self._hosts)

    def __getitem__(self, ip):
        return self._hosts[ip]


def test_extract_major_minor():
    assert scanner.extract_major_minor("OpenSSH 9.6p1 Ubuntu") == "9.6"
    assert scanner.extract_major_minor("unknown") == ""
    assert scanner.extract_major_minor(None) == ""


def test_parse_results_builds_hosts_and_services():
    ports = {"tcp": {
        22: {"state": "open", "product": "OpenSSH", "version": "9.6p1"},
        80: {"state": "closed", "product": "nginx", "version": "1.24"},
    }}
    port_scanner = FakePortScanner({"10.0.4.10": FakeHost("10.0.4.10", "up", ports)})

    hosts = scanner.parse_results(port_scanner)
    assert len(hosts) == 1
    assert hosts[0].ip == "10.0.4.10"
    assert len(hosts[0].services) == 1
    service = hosts[0].services[0]
    assert service.port == 22
    assert service.protocol == "tcp"
    assert service.product == "OpenSSH"
    assert service.version == "9.6p1"
    assert service.major_minor == "9.6"


def test_parse_results_skips_down_host_and_malformed_results(capsys):
    down = FakeHost("10.0.4.11", "down", {})
    malformed = FakeHost("10.0.4.12", "up", {"tcp": {22: {"state": "open"}}})
    port_scanner = FakePortScanner({"10.0.4.11": down, "10.0.4.12": malformed})

    hosts = scanner.parse_results(port_scanner)
    assert hosts == []
    assert "malformed result" in capsys.readouterr().err


def test_parse_results_warns_for_unknown_banner(capsys):
    ports = {"tcp": {22: {"state": "open", "product": "", "version": ""}}}
    port_scanner = FakePortScanner({"10.0.4.10": FakeHost("10.0.4.10", "up", ports)})

    hosts = scanner.parse_results(port_scanner)
    assert len(hosts) == 1
    assert "banner not identified" in capsys.readouterr().err


def test_run_scan_validates_whitelist(monkeypatch):
    allowed = None
    def fake_validate(target, whitelist):
        assert target == "10.0.4.0/24"
        assert whitelist is allowed
        return "10.0.4.0/24"

    monkeypatch.setattr(scanner, "validate_target", fake_validate)
    monkeypatch.setattr(scanner.nmap, "PortScanner", lambda: FakePortScanner({}))
    assert scanner.run_scan("10.0.4.0/24") == []


def test_run_scan_timeout(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "validate_target", lambda target, whitelist: "10.0.4.0/24")

    class TimeoutScanner:
        def scan(self, **kwargs):
            raise scanner.nmap.PortScannerTimeout("timeout")

    monkeypatch.setattr(scanner.nmap, "PortScanner", TimeoutScanner)
    assert scanner.run_scan("10.0.4.0/24", timeout=42) == []
    assert "timed out" in capsys.readouterr().err


def test_run_scan_nmap_error(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "validate_target", lambda target, whitelist: "10.0.4.0/24")

    class ErrorScanner:
        def scan(self, **kwargs):
            raise scanner.nmap.PortScannerError("nmap missing")

    monkeypatch.setattr(scanner.nmap, "PortScanner", ErrorScanner)
    assert scanner.run_scan("10.0.4.0/24") == []
    assert "nmap error" in capsys.readouterr().err
