#!/usr/bin/env python3
import argparse
import asyncio
import colorlog
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config.scanner_config import ScannerConfig, load_scanner_config
from .reporting.report_generator import generate_report
from .scanner.vulnerability_scanner import VulnerabilityScanner as Scanner


def get_app_dir() -> Path:
    """Return the project root directory."""
    return Path(__file__).resolve().parent.parent.parent


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    handler = colorlog.StreamHandler(stream=sys.stdout)
    handler.setFormatter(colorlog.ColoredFormatter(
        fmt="%(log_color)s[%(levelname)s]%(reset)s "
            "%(yellow)s%(asctime)s%(reset)s: "
            "%(blue)s%(message)s%(reset)s",
        datefmt="%H:%M:%S",
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "bold_red",
        },
    ))
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    logging.basicConfig(level=level, handlers=[handler], force=True)


def normalize_target_url(url: str) -> str:
    """Ensure a scheme is present before scanning."""
    return url if url.startswith(("http://", "https://")) else f"https://{url}"


def build_runtime_config(args: argparse.Namespace) -> ScannerConfig:
    """Combine defaults, YAML, and CLI values into one config object."""
    config_data = load_scanner_config(args.config) if args.config else ScannerConfig()
    config_data.update({
        "target_url": normalize_target_url(args.url),
        "modules": args.modules,
        "active_tests": args.active_tests,
    })
    return config_data


def build_output_path(output_argument: Optional[str], report_format: str) -> Path:
    """Build the final report path."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = get_app_dir() / "reports"
    reports_dir.mkdir(exist_ok=True)

    if output_argument:
        output_file = Path(output_argument).resolve()
    else:
        output_file = reports_dir / f"scan_report_{timestamp}.{report_format}"

    output_file.parent.mkdir(parents=True, exist_ok=True)
    return output_file


async def run_scan(config: ScannerConfig):
    """Run the scan engine and return results."""
    scanner = Scanner(config)
    return await scanner.scan()


def run_scanner():
    """Main entry point for the scanner."""
    parser = argparse.ArgumentParser(
        description=(
            "Web Application Security Scanner — scans a target URL for common "
            "web vulnerabilities and generates a structured report."
        ),
        epilog=(
            "Examples:\n"
            "  python main.py --url https://example.com\n"
            "  python main.py --url https://example.com --format json --verbose\n"
            "  python main.py --url https://example.com --config config/scanner_config.yaml\n"
            "\n"
            "Always obtain written permission before scanning a site you do not own."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--url", required=True, help="Target URL to scan")
    parser.add_argument("--config", help="Path to a YAML config file")
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=["recon"],
        default=["recon"],
        help="Modules to run (default: recon)",
    )
    parser.add_argument(
        "--active-tests",
        action="store_true",
        help="Enable active injection tests (authorized targets only)",
    )
    parser.add_argument(
        "--output",
        help="Path for the report file (default: reports/scan_report_<timestamp>.<format>)",
    )
    parser.add_argument("--format", choices=["json", "html", "pdf"], default="html")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    try:
        setup_logging(args.verbose)
        config_data = build_runtime_config(args)
        results = asyncio.run(run_scan(config_data))

        if not results:
            return 1

        output_file = build_output_path(args.output, args.format)
        generate_report(
            scan_results=results,
            output_format=args.format,
            output_file=str(output_file),
        )

        logging.info("Report saved to: %s", output_file)
        return 0
    except Exception as e:
        logging.error("Scan failed: %s", str(e), exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(run_scanner())
