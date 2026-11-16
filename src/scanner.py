import re
import sys
from dataclasses import dataclass, field

import nmap

from whitelist import validate_target

NMAP_TIMEOUT_SECONDS = 300
NMAP_ARGUMENTS = "-sV --open --host-timeout 60s"
VERSION_PATTERN = re.compile(r"(\d+)\.(\d+)")


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    product: str
    version: str
    major_minor: str


@dataclass
class Host:
    ip: str
    services: list = field(default_factory=list)


def log_warning(message):
    print(f"WARNING: {message}", file=sys.stderr)


def extract_major_minor(version):
    match = VERSION_PATTERN.search(version or "")
    return f"{match.group(1)}.{match.group(2)}" if match else ""


def parse_results(port_scanner):
    # convert the python-nmap results into Host and Service objects
    hosts = []
    for ip in port_scanner.all_hosts():
        try:
            if port_scanner[ip].state() != "up":
                continue
            host = Host(ip=ip)
            for protocol in port_scanner[ip].all_protocols():
                for port, details in port_scanner[ip][protocol].items():
                    if details["state"] != "open":
                        continue
                    if not details["product"]:
                        log_warning(f"{ip}:{port} banner not identified")
                    host.services.append(Service(
                        port=int(port),
                        protocol=protocol,
                        product=details["product"],
                        version=details["version"],
                        major_minor=extract_major_minor(details["version"]),
                    ))
            hosts.append(host)
        except (KeyError, TypeError, ValueError):
            log_warning(f"malformed result for {ip} skipped")
    return hosts


def run_scan(target, whitelist=None, timeout=NMAP_TIMEOUT_SECONDS):
    # Validate before invoking nmap; WhitelistError is left for the caller.
    network = validate_target(target, whitelist)
    try:
        port_scanner = nmap.PortScanner()
        port_scanner.scan(hosts=str(network), arguments=NMAP_ARGUMENTS, timeout=timeout)
    except nmap.PortScannerTimeout:
        log_warning(f"scan of {network} timed out after {timeout}s")
        return []
    except nmap.PortScannerError as error:
        log_warning(f"nmap error: {error}")
        return []
    return parse_results(port_scanner)