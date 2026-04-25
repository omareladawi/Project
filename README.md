# Web Application Security Scanner

A final-year graduation project: an asynchronous web security scanner that performs
reconnaissance and common vulnerability checks, then produces structured HTML, JSON,
or PDF reports.

> ⚠️ **Authorisation required.** Always obtain explicit written permission before
> scanning any host you do not personally own.

---

## Quick Start (3 commands)

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Run a basic recon scan (safe default)
webscan --url https://example.com

# 3. Save results as JSON instead of HTML
webscan --url https://example.com --format json
```

Reports are written to the `reports/` folder automatically.

---

## Installation

```bash
git clone https://github.com/omareladawi/Project.git
cd Project
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Usage

### Basic

```bash
webscan --url https://example.com
```

### With options

```bash
webscan --url https://example.com \
        --format html \
        --verbose
```

### All CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | *(required)* | Target URL to scan |
| `--format` | `html` | Report format: `html` \| `json` \| `pdf` |
| `--output` | auto | Custom output file path |
| `--config` | built-in | Path to a YAML config file |
| `--verbose` | off | Print debug-level messages |

---

## What It Scans

The scanner runs a **recon** module that checks:

- Security headers (HSTS, X-Frame-Options, CSP, etc.)
- SSL/TLS configuration
- Information disclosure (server version, directory listing, email leaks)
- Common injection patterns (XSS, SQL injection, command injection)

---

## Project Structure

```
Project/
├── src/
│   └── web_scanner/
│       ├── config/             # Config loader (scanner_config.py)
│       ├── core/               # Shared utilities
│       ├── scanner/            # Scanning engine
│       │   ├── vulnerability_scanner.py   # Main scan orchestrator
│       │   └── modules/
│       │       └── reconnaissance.py      # Recon checks
│       ├── reporting/          # Report generation (HTML / JSON / PDF)
│       ├── types.py            # Shared data classes (ScannerConfig, …)
│       └── main.py             # CLI entry point
├── config/
│   ├── scanner_config.yaml              # Full config with all options
│   └── scanner_config.student.yaml      # Minimal demo-ready config
├── tests/                      # Pytest tests for findings processing
├── requirements.txt
└── pyproject.toml
```

---

## Execution Pipeline

```
CLI → config load → scanner → finding processing → report
```

1. **CLI** — parse flags, load config, apply CLI overrides.
2. **Config** — `ScannerConfig` (defaults) + optional YAML override.
3. **Scanner** — `VulnerabilityScanner.scan()` runs the recon module and collects raw findings.
4. **Finding processing** — deduplicate, assign confidence scores, adjust severity.
5. **Report** — `generate_report()` writes an HTML / JSON / PDF file to `reports/`.

---

## Configuration

Two config files are provided:

| File | Use case |
|------|----------|
| `config/scanner_config.yaml` | Full reference — all options documented |
| `config/scanner_config.student.yaml` | Minimal, demo-safe defaults |

Key options:

```yaml
threads: 5                  # Parallel workers
timeout: 20                 # Seconds per request
requests_per_second: 3.0    # Throttle (be polite)
max_urls_per_domain: 50     # Crawl limit
min_confidence_score: 0.6   # Drop low-confidence findings
result_deduplication: true  # Remove duplicates automatically
```

---

## Reporting

The scanner produces three report formats:

- **HTML** (default) — visual report with findings table and risk summary.
- **JSON** — machine-readable; useful for further processing.
- **PDF** — printable version for project submission.

Reports include: target info, scan duration, findings list with severity / confidence
scores / evidence / remediation guidance, and an overall risk score.

---

## Running Tests

```bash
pytest tests/ -v
```

All 8 tests cover findings deduplication, confidence scoring, and severity adjustment —
the core of the reporting pipeline.

---

## Security Considerations

- Always get written authorisation before scanning.
- Respect the target's rate limits and `robots.txt`.
- Treat scanner output as *indicators* — manually validate important findings before
  making remediation decisions.

---

## Acknowledgement

This project was developed as a final-year graduation project using AI-assisted tools
and open-source libraries. Feedback and suggestions are welcome.
