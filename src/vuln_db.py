import json
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_S = 10
MIN_GAP_NO_KEY_S = 6.0
MIN_GAP_WITH_KEY_S = 0.6
DEFAULT_DB_PATH = "cve_cache.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"
CVSS_V3_KEYS = ("cvssMetricV31", "cvssMetricV30")

# nmap product name -> search term NVD understands
PRODUCT_ALIASES = {
    "apache httpd": "apache http server",
    "samba smbd": "samba",
    "postgresql db": "postgresql",
}

VERSION_PATTERN = re.compile(r"(\d+)\.(\d+)")


def normalise_product(product):
    """Lowercase and collapse whitespace. Non-strings give an empty string."""
    if not isinstance(product, str):
        return ""
    return " ".join(product.lower().split())


def normalise_version(version):
    """Reduce a version string to 'major.minor'; None if it has no such part."""
    if not isinstance(version, str):
        return None
    match = VERSION_PATTERN.search(version)
    if match is None:
        return None
    return f"{match.group(1)}.{match.group(2)}"


def _warn(message):
    print(f"WARNING: {message}", file=sys.stderr)


class VulnDB:
    def __init__(self, db_path=DEFAULT_DB_PATH, api_key=None, offline=False):
        self._api_key = api_key
        self._offline = offline
        self._last_request_time = None
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    # ---------- lifecycle ----------
    def _init_schema(self):
        self._conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    # ---------- cache ----------
    def get_cached(self, product, version):
        """Return [(cve_id, exploitability)] or None if never looked up.

        An empty list means 'looked up, no CVEs found'.
        """
        product = normalise_product(product)
        version = normalise_version(version)
        if not product or version is None:
            return None
        row = self._conn.execute(
            "SELECT service_id FROM services WHERE product = ? AND version = ?",
            (product, version),
        ).fetchone()
        if row is None:
            return None
        rows = self._conn.execute(
            "SELECT c.cve_id, c.exploitability "
            "FROM service_cves sc JOIN cves c ON c.cve_id = sc.cve_id "
            "WHERE sc.service_id = ? "
            "ORDER BY c.exploitability DESC, c.cve_id",
            (row[0],),
        ).fetchall()
        return [(cve_id, score) for cve_id, score in rows]

    def store(self, product, version, cves):
        """Store a lookup result. Each cve is (cve_id, exploitability
        [, base_score [, description]])."""
        product = normalise_product(product)
        version = normalise_version(version)
        if not product or version is None:
            raise ValueError("cannot store: invalid product or version")
        now = datetime.now(timezone.utc).isoformat()
        with self._conn:  # one transaction: all or nothing
            self._conn.execute(
                "INSERT OR IGNORE INTO services (product, version) VALUES (?, ?)",
                (product, version),
            )
            self._conn.execute(
                "UPDATE services SET last_checked = ? "
                "WHERE product = ? AND version = ?",
                (now, product, version),
            )
            service_id = self._conn.execute(
                "SELECT service_id FROM services WHERE product = ? AND version = ?",
                (product, version),
            ).fetchone()[0]
            for cve in cves:
                cve_id, exploitability, base_score, description = (
                    tuple(cve) + (None, None)
                )[:4]
                self._conn.execute(
                    "INSERT OR IGNORE INTO cves "
                    "(cve_id, exploitability, base_score, description) "
                    "VALUES (?, ?, ?, ?)",
                    (cve_id, exploitability, base_score, description),
                )
                self._conn.execute(
                    "INSERT OR IGNORE INTO service_cves (service_id, cve_id) "
                    "VALUES (?, ?)",
                    (service_id, cve_id),
                )

    # ---------- public lookup ----------
    def get_vulnerabilities(self, product, version):
        product = normalise_product(product)
        version = normalise_version(version)
        if not product or version is None:
            return []

        cached = self.get_cached(product, version)
        if cached is not None:
            return cached
        if self._offline:
            return []

        try:
            cves = self._fetch_nvd(product, version)
        except (OSError, ValueError, KeyError, TypeError) as error:
            _warn(f"NVD lookup failed for {product} {version}: {error}")
            return []

        self.store(product, version, cves)
        return self.get_cached(product, version)

    # ---------- NVD client ----------
    def _respect_rate_limit(self):
        gap = MIN_GAP_WITH_KEY_S if self._api_key else MIN_GAP_NO_KEY_S
        if self._last_request_time is not None:
            wait = gap - (time.monotonic() - self._last_request_time)
            if wait > 0:
                time.sleep(wait)
        self._last_request_time = time.monotonic()

    def _fetch_nvd(self, product, version):
        self._respect_rate_limit()
        search_term = PRODUCT_ALIASES.get(product, product)
        query = urllib.parse.urlencode({"keywordSearch": f"{search_term} {version}"})
        request = urllib.request.Request(f"{NVD_URL}?{query}")
        if self._api_key:
            request.add_header("apiKey", self._api_key)
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_S) as response:
            payload = json.load(response)
        return self._parse_nvd(payload, product, search_term, version)

    @staticmethod
    def _parse_nvd(payload, product, search_term, version):
        terms = {product, search_term, search_term.replace(" ", "_")}
        results = []
        for item in payload.get("vulnerabilities", []):
            cve = item["cve"]
            score = VulnDB._extract_v3_scores(cve)
            if score is None:
                continue  # v2-only CVEs use a different 0-10 scale: skipped
            if not VulnDB._mentions(cve, terms, version):
                continue  # keyword search is noisy: filter out unrelated CVEs
            exploitability, base_score = score
            results.append(
                (cve["id"], exploitability, base_score, VulnDB._english(cve))
            )
        return results

    @staticmethod
    def _extract_v3_scores(cve):
        metrics = cve.get("metrics", {})
        for key in CVSS_V3_KEYS:
            entries = metrics.get(key)
            if entries:
                entry = entries[0]
                return entry["exploitabilityScore"], entry["cvssData"]["baseScore"]
        return None

    @staticmethod
    def _english(cve):
        for description in cve.get("descriptions", []):
            if description.get("lang") == "en":
                return description.get("value", "")
        return ""

    @staticmethod
    def _mentions(cve, terms, version):
        haystack = VulnDB._english(cve).lower()
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    haystack += " " + match.get("criteria", "").lower()
        return any(term in haystack for term in terms) and version in haystack