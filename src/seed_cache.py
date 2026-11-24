import argparse

from vuln_db import DEFAULT_DB_PATH, VulnDB

# Replace
DEFAULT_SERVICES = [
    ("vsftpd", "2.3.4"),
    ("openssh", "4.7"),
    ("apache httpd", "2.2.8"),
    ("proftpd", "1.3.1"),
    ("samba smbd", "3.0.20"),
    ("mysql", "5.0.51a"),
    ("postgresql db", "8.3"),
]


def parse_service(text):
    product, _, version = text.rpartition(":")
    return product, version


def main():
    parser = argparse.ArgumentParser(description="Seed the local CVE cache.")
    parser.add_argument("services", nargs="*", help="product:version pairs")
    parser.add_argument("--db", default=DEFAULT_DB_PATH)
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()

    services = [parse_service(s) for s in args.services] or DEFAULT_SERVICES
    with VulnDB(args.db, api_key=args.api_key) as database:
        for product, version in services:
            results = database.get_vulnerabilities(product, version)
            print(f"{product} {version}: {len(results)} CVEs")


if __name__ == "__main__":
    main()