# Web Application Security Scanner

A final-year graduation project: an asynchronous web security scanner that performs
reconnaissance and common vulnerability checks, then produces structured HTML, JSON,
or PDF reports.

> ⚠️ **Authorisation required.** Always obtain explicit written permission before
> scanning any host you do not personally own.



## Quick Start (3 commands)

```bash
# 1. Install
pip install -r requirements.txt

# 2. Run a basic recon scan (safe default)
python main.py --url https://example.com

# 3. Save results as JSON instead of HTML
python main.py --url https://example.com --format json
```

Reports are written to the `reports/` folder automatically.

---

## Installation

```bash
git clone https://github.com/omareladawi/Project.git
cd Project
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Basic

```bash
python main.py --url https://example.com
```

### With options

```bash
python main.py --url https://example.com \
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
| `--active-tests` | off | Enable active XSS/SQLi tests (authorized targets only) |
| `--verbose` | off | Print debug-level messages |

---

## What It Scans

The scanner runs a **recon** module that checks:

- Security headers (HSTS, X-Frame-Options, CSP, etc.)
- SSL/TLS configuration
- Information disclosure (server version, directory listing, email leaks)
- Common injection patterns (XSS, SQL injection, command injection)
- Basic auth/session hygiene (CSRF hints, cookie flags)

---

## Project Structure

```
Project/
├── src/
│   └── web_scanner/
│       ├── config/             # Config loader (scanner_config.py)
│       ├── core/               # Shared utilities
│       ├── scanner/            # Scanning engine
│       │   └── vulnerability_scanner.py   # Main scan orchestrator
│       ├── reporting/          # Report generation (HTML / JSON / PDF)
│       ├── types.py            # Shared data classes (ScannerConfig, …)
│       └── main.py             # CLI entry point
├── config/
│   └── scanner_config.yaml              # Minimal config
├── requirements.txt
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

Single config file:

- `config/scanner_config.yaml`

Key options:

```yaml
timeout: 30
verify_ssl: false
user_agent: "WebSecurityScanner/1.0"
modules:
  - recon
result_deduplication: true
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

## Security Considerations

- Always get written authorisation before scanning.
- Respect the target's rate limits and `robots.txt`.
- Treat scanner output as *indicators* — manually validate important findings before
  making remediation decisions.

---

## Acknowledgement

This project was developed as a final-year graduation project using AI-assisted tools
and open-source libraries. Feedback and suggestions are welcome.
