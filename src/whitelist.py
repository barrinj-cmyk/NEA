import csv
import ipaddress
from pathlib import Path

WHITELIST_PATH = Path(__file__).resolve().parent.parent / "data" / "whitelist.csv"
MIN_PREFIX = 16


class WhitelistError(Exception):
    pass


def load_whitelist(path=WHITELIST_PATH):
    # fail if the whitelist file is missing or empty
    networks = []
    try:
        with open(path) as file:
            reader = csv.reader(file)
            next(reader)  # skip the header row
            for row in reader:
                # strip before the comment check
                if row and row[0].strip() and not row[0].strip().startswith("#"):
                    network = ipaddress.ip_network(row[0].strip(), strict=True)
                    if network.version != 4 or not network.is_private or network.prefixlen < MIN_PREFIX:
                        raise ValueError(f"{network} is not a private IPv4 range of /{MIN_PREFIX} or narrower")
                    networks.append(network)
    except (OSError, ValueError, StopIteration) as error:
        raise WhitelistError(f"Cannot load whitelist: {error}") from error

    if len(networks) == 0:
        raise WhitelistError("Whitelist is empty")
    return networks


def is_whitelisted(target, whitelist):
    try:
        target_network = ipaddress.ip_network(target.strip(), strict=False)
    except (ValueError, AttributeError):
        return False  # Wrong input format
    for allowed in whitelist:
        if target_network.version == allowed.version and target_network.subnet_of(allowed):
            return True
    return False


def validate_target(target, whitelist=None):
    if whitelist is None:
        whitelist = load_whitelist()
    if not is_whitelisted(target, whitelist):
        raise WhitelistError(f"Target {target} is not in the whitelist")
    return ipaddress.ip_network(target.strip(), strict=False)