# NEA Recon & Vulnerability Chaining Tool

A lightweight, locally run tool that takes scan data from a small network and finds the **lowest-effort attack path** between an entry host and a target host, instead of a flat list of CVEs ranked by severity.

> **Authorised use only.** The tool enforces an IP whitelist and refuses to scan outside the lab subnet. It is a passive scanner and analyser: it contains no exploitation, payload, shell or packet-manipulation code.

## How it works

```
CLI -> Orchestrator
        |-> Scanner (nmap -sV, IP whitelist)
        |-> Vulnerability matcher (SQLite cache -> NVD API fallback)
        |-> Graph builder (hosts = nodes, exploitable CVEs = weighted edges)
        |-> Algorithms (Dijkstra + custom min-heap, BFS baseline)
        |-> Reporter (Markdown narrative)
```

1. **Discover** live hosts, open ports and service versions with `nmap -sV`.
2. **Match** each service (product + major.minor version) to CVEs from a local SQLite cache, falling back to the NVD API when a service is not cached.
3. **Build** a directed graph. Edge weights are derived from the inverted CVSS exploitability score, so easier exploits cost less.
4. **Search** with Dijkstra (backed by a hand-written binary min-heap) for the lowest-cost path, and BFS for the fewest-hops baseline.
5. **Report** the path in plain English with per-step reasoning, cumulative cost and a comparison with the BFS result. If no route exists, it says so explicitly.

---

## Status

| Component | File | Status |
|---|---|---|
| Network discovery + IP whitelist | `src/scanner.py` | Phase 1 |
| Binary min-heap | `src/heap.py` | Written, tests in `tests/test_heap.py` |
| CVE cache + NVD client | `src/vuln_db.py`, `src/schema.sql` | Written, tests in `tests/test_vuln_db.py` |
| Cache seeding script | `src/seed_cache.py` | Written |
| Graph model, Dijkstra, BFS | `src/graph.py` | Planned (Week 5) |
| Narrative reporter | `src/reporter.py` | Planned (Week 6) |
| CLI + orchestrator | `src/cli.py` | Planned (Week 7) |

Automated tests are in `tests/`; run them with `pytest -v`.

---

## Repository layout

```
.
├── pytest.ini               # pythonpath = src, testpaths = tests
├── README.md
├── src/
│   ├── heap.py              # MinHeap, zero dependencies on other project code
│   ├── vuln_db.py           # VulnDB: SQLite cache + NVD API v2.0 client
│   ├── schema.sql           # cves / services / service_cves tables
│   ├── seed_cache.py        # fills the cache while online
│   ├── scanner.py           # nmap wrapper + whitelist
│   ├── graph.py             # (planned)
│   ├── reporter.py          # (planned)
│   └── cli.py               # (planned)
├── tests/
│   ├── test_heap.py
│   ├── test_vuln_db.py
│   └── fixtures/            # frozen cve_cache.db, sample nmap XML
├── lab/                     # lab VM configuration
└── docs/evidence/           # test and lab screenshots for the write-up
```

---

## Setup

Requirements: Python 3.9+, `nmap` installed on the system, `pytest`.

```bash
sudo apt install nmap
pip install pytest
```

Run everything from the **project root** so relative paths such as `cve_cache.db` resolve correctly.

### Seed the CVE cache (once, while online)

```bash
python src/seed_cache.py                              # default lab services
python src/seed_cache.py vsftpd:2.3.4 "samba smbd:3.0.20"
python src/seed_cache.py --api-key YOUR_NVD_KEY       # optional, faster rate limit
```

Then freeze a copy for offline use and tests:

```bash
cp cve_cache.db tests/fixtures/cve_cache.db
```

### Run the tests

```bash
pytest -v
```

No test touches the real network; NVD calls are mocked.

---

## Usage (planned CLI)

```bash
python src/cli.py --target-subnet 10.0.4.0/24 \
                  --entry-node 10.0.4.10 \
                  --target-node 10.0.4.20 \
                  [--api-key KEY] [--output report.md]
```

| Flag | Purpose |
|---|---|
| `--target-subnet` | CIDR to scan; must fall inside the whitelisted lab range |
| `--entry-node` | Where the attacker starts |
| `--target-node` | Host to reach |
| `--api-key` | Optional NVD API key |
| `--output` | Write the Markdown report to a file instead of stdout |

Out-of-whitelist targets exit with code 1.

---

## Module notes

### `heap.py`
`MinHeap` stores `(priority, element)` tuples in an array, with a position map (`element -> index`) so `decrease_key` is O(log n).

| Method | Behaviour |
|---|---|
| `push(priority, element)` | Insert; `ValueError` if the element is already present |
| `pop_min()` | Remove and return the smallest; `IndexError` if empty |
| `peek()` | Return the smallest without removing it |
| `decrease_key(element, new_priority)` | `KeyError` if missing, `ValueError` if the new priority is higher |
| `len()`, `in`, `is_empty()` | Size and membership checks |

### `vuln_db.py`
`VulnDB(db_path, api_key=None, offline=False)`

| Method | Behaviour |
|---|---|
| `get_vulnerabilities(product, version)` | Cache first, API fallback, caches the result. Never raises on network or parse errors: returns `[]` and warns on stderr |
| `get_cached(product, version)` | `None` = never looked up, `[]` = looked up with no CVEs |
| `store(product, version, cves)` | Transactional insert across the three tables |

Design decisions:
- Lookups are keyed on **normalised product and major.minor version** (`2.3.4` -> `2.3`).
- A **failed** network lookup is never cached, so one offline run cannot poison the cache.
- `offline=True` guarantees no network calls (although this is changable).
- NVD requests are rate-limited (about 6 s apart without a key).
- All SQL is parameterised.

### Database schema
- `cves(cve_id PK, exploitability, base_score, description)`
- `services(service_id PK, product, version, last_checked, UNIQUE(product, version))`
- `service_cves(service_id FK, cve_id FK, PK(service_id, cve_id))`

---

## Lab environment

Testing runs in an isolated virtual network so the tool never touches real systems.

- QEMU/KVM with virt-manager
- Isolated libvirt network `nea-lab`, `10.0.4.0/24` (host `10.0.4.1`)
- Targets: `meta2-a` and `meta2-b` (Metasploitable 2 overlays on a read-only base image)
- A clean "no path" VM is planned for testing the no-path result

---


## Known limitations

- Version matching is exact on **product + major.minor** only. No CPE 2.3 matching or version ranges.
- NVD keyword search is noisy. Results are filtered by checking that the description or CPE data mentions the product and version, so some genuine matches may be missed.
- CVEs that only have CVSS v2 scores have their exploitability scaled linearly from 0-10 to the v3 range of 0-3.9. This is an approximation.
- nmap sometimes reports version ranges (e.g. Samba `3.X - 4.X`), which cannot be normalised and return no CVEs unless overridden.
- Single lowest-cost path only: no k-shortest paths or probabilistic risk scoring.
- CLI only

---

## Legal and ethical

Only scan networks you own or have written permission to test. The whitelist is a safeguard, not a substitute for authorisation. The tool performs no exploitation.
