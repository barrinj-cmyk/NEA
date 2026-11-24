CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    exploitability REAL NOT NULL,
    base_score REAL,
    description TEXT
);
CREATE TABLE IF NOT EXISTS services (
    service_id INTEGER PRIMARY KEY AUTOINCREMENT,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    last_checked TEXT,
    UNIQUE(product, version)
);
CREATE TABLE IF NOT EXISTS service_cves (
    service_id INTEGER NOT NULL REFERENCES services(service_id),
    cve_id TEXT NOT NULL REFERENCES cves(cve_id),
    PRIMARY KEY (service_id, cve_id)
);