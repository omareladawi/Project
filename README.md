## Execution Pipeline

```
CLI  →  config load  →  scanner  →  finding processing  →  report
```

1. **CLI** — You run one of:
   ```bash
   python3 main.py --url https://example.com --modules recon --format html --verbose
   webscan --url https://example.com --modules recon --format html
   python -m web_scanner.main --url https://example.com --modules recon --format html
   ```
2. **Config load** — Default settings come from `ScannerConfig` in `src/web_scanner/types.py`.  
   Pass `--config config/scanner_config.yaml` to override threads, timeouts, etc.
3. **Scanner** — `VulnerabilityScanner.scan()` runs the selected modules (recon / brute / exploit)
   and collects raw findings.
4. **Finding processing** — Findings are deduplicated, confidence-scored, and severity-adjusted.
5. **Report** — `generate_report()` writes an HTML/JSON/PDF file to the `reports/` directory.

> ⚠️ Findings are indicators from automated checks and **require manual validation** before
> treating them as confirmed vulnerabilities.

---

## Project Structure
```
## Project Structure
```bash
web-scanner/
├── src/
│   └── web_scanner/
│       ├── config/                 # Configuration management
│       ├── core/                   # Core functionality
│       ├── scanner/                # Security scanning modules
│       ├── reporting/              # Report generation
│       ├── types.py                # Type definitions
│       ├── crawler.py              # Web crawler functionality
│       └── main.py                 # CLI entry point
├── .env.example                    # Environment variables template
├── config/                         # Default configurations
├── NOTICE.md                       # Attribution and license context
├── pyproject.toml
├── requirements.txt
└── setup.py
```

## Core Features

### Scanner Architecture
- Modular design with specialized components for different security tests
- Asynchronous scanning engine for improved performance
- Real-time progress monitoring and reporting
- Configurable scan parameters and modules
- Rate limiting and proxy support
- Session management and authentication handling

### Security Testing Modules

#### 1. Reconnaissance Module
- Port scanning and service detection
- Subdomain enumeration 
- Technology stack fingerprinting
- Server information gathering
- Banner grabbing
- Service version detection

#### 2. Authentication Tests
- CSRF token validation
- Session management analysis
- Password policy assessment 
- Authentication bypass detection
- Token security verification
- Session timeout checks

#### 3. Vulnerability Scanning
- SQL Injection patterns detection
- Cross-site Scripting (XSS) analysis
- Command injection testing
- XML External Entity (XXE) checks
- Local/Remote File Inclusion tests
- Deserialization vulnerability checks

#### 4. Configuration Analysis
- Security header validation
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Strict-Transport-Security
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
- SSL/TLS configuration assessment
- Server information disclosure checks
- Error handling analysis
- Directory listing detection

#### 5. Information Disclosure
- Sensitive data exposure detection
  - Email addresses
  - Phone numbers
  - API keys
  - Credentials
  - Credit card numbers
- Directory traversal testing
- Version information leakage
- Error message analysis

### Advanced Features

#### Scan Configuration
- Customizable scan depth and thread count
- Configurable request rates and timeouts
- Proxy support with rotation
- Custom user agent strings
- Path exclusion rules
- Authentication configuration

#### Result Analysis
- Confidence scoring system
- False positive reduction
- Result deduplication
- Finding validation
- Severity classification
- Evidence collection
- Remediation guidance

## Installation

1. Clone the repository:
```bash
https://github.com/omareladawi/Project.git
cd web-scanner
```

2. Install package in development mode:
```bash
pip install -e .
```

### Development

- Run Options (quick start):
  ```bash
  python3 main.py --url https://example.com --modules recon --format html --verbose
  ```
- Runtime install:
  ```bash
  pip install -e .
  ```
- Install development dependencies:
  ```bash
  pip install -e ".[dev]"
  ```
- Run from CLI:
  ```bash
  webscan --url https://example.com --modules recon --format html
  ```
- Run as Python module:
  ```bash
  python -m web_scanner.main --url https://example.com --modules recon --format html
  ```

- Recommended virtual environment flow:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[dev]"
  webscan --url https://example.com --modules recon --format html
  ```

## Usage

### Command Line Interface

#### Basic Usage
Run quick scans with minimal configuration:
```bash
webscan --url example.com
```

#### Advanced Usage
Execute comprehensive scans with multiple modules:
```bash
webscan --url example.com  --modules recon exploit brute    --verbose
```

#### report formats reporting:

The scanner generates comprehensive security assessment reports in the following formats:

- **PDF**: Portable document format suitable for sharing and printing

To specify the report format when running a scan:

```bash

# For PDF format
webscan --url example.com --format pdf
```

PDF Reports
- Professional formatting
- Executive summary
- Technical details
- Finding categorization
- Evidence documentation
- Remediation steps



# security audit
webscan --url example.com --modules recon brute exploit
```

Command line options:
```bash
--url: Target URL/domain to scan (required)
--modules: Modules to run (recon,auth,injection,config)
--format: Output format (json|html|pdf, default: html)
--output-dir: Directory for scan reports (default: "reports")
--verbose: Enable verbose logging
--config: Path to custom configuration file
```


### Example Usage

Using the provided example:
```python
from web_scanner.config.scanner_config import ScannerConfig
from web_scanner.scanner.vulnerability_scanner import VulnerabilityScanner

# Load config
config = ScannerConfig.from_yaml('config/scanner_config.yaml')

# Initialize scanner
scanner = VulnerabilityScanner(config)

# Run scan
target = "https://example.com"
results = scanner.scan(target)
```

### Configuration

```bash
# Core Settings
threads: 10
timeout: 30
max_crawl_depth: 3
verify_ssl: false

# Rate Limiting
requests_per_second: 10.0
burst_size: 10

# Scan Controls
max_urls_per_domain: 100
max_test_duration: 300
skip_similar_endpoints: true

# Result Processing
min_confidence_score: 0.7
max_false_positives: 5
result_deduplication: true

# Test Weights
test_weights:
  critical: 1.0
  high: 0.8
  medium: 0.6
  low: 0.4
  info: 0.2
```

## Security Considerations

- Obtain proper authorization before scanning
- Respect rate limits and robots.txt
- Use responsibly and ethically
- Test thoroughly in isolated environments
- Findings are indicators from automated checks and may require manual validation to confirm true positives.
- Treat scanner output as security indicators; always manually validate important findings before remediation decisions.

## Acknowledgment

This project, Web Scanner, was developed using AI-assisted tools.

I appreciate the role of AI in enhancing productivity and welcome any feedback or suggestions for improvement.






nottttteeee 

the tool is still in construction it will inshaa-allah developed before july
