#!/usr/bin/env python3

import argparse
import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config.scanner_config import load_scanner_config, ScannerConfig
from .scanner.vulnerability_scanner import VulnerabilityScanner as Scanner
from .reporting.report_generator import generate_report

def get_app_dir() -> Path:
    """Returns the base directory for the application"""
    return Path(__file__).parent.parent.parent

def setup_logging(verbose: bool, log_file: Optional[Path] = None) -> None:
    """Configure logging settings"""
    level = logging.DEBUG if verbose else logging.INFO
    
    handlers = [logging.StreamHandler()]
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_file)))
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

async def run_scan(config: ScannerConfig) -> dict:
    """Run the security scan"""
    scanner = Scanner(config)
    return await scanner.scan()


# ---------------------------------------------------------------------------
# run_scanner() is the PRIMARY entrypoint — used by `webscan`, `python3
# main.py`, and `python -m web_scanner.main`.
#
# The async def main() that used to be here was a broken legacy stub
# (wrong argument signature, awaiting a non-async generate_report, etc.)
# and has been removed.  All run modes go through run_scanner() below.
# ---------------------------------------------------------------------------

def run_scanner():
    """Main entry point for the scanner"""
    parser = argparse.ArgumentParser(description='Web Application Security Scanner')
    
    # Required arguments
    parser.add_argument('--url', required=True, help='Target URL to scan')
    
    # Scan configuration
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--modules', nargs='+', choices=['recon', 'brute', 'exploit'],
                       default=['recon'], help='Modules to run (default: recon)')
    
    # Output options
    parser.add_argument('--output', help='Output file for the report')
    parser.add_argument('--format', choices=['json', 'html', 'pdf'], default='html',
                       help='Output format (default: html)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()

    try:
        # Load base config
        config_data = load_scanner_config(args.config) if args.config else ScannerConfig()
        
        # Create new config with CLI overrides
        cli_config = {
            'target_url': args.url if args.url.startswith(('http://', 'https://')) else f'https://{args.url}',
            'modules': args.modules,
            'report_format': args.format,
        }
        
        # Setup logging before updating config
        setup_logging(args.verbose)
        
        # Apply CLI overrides to config
        config_data.update(cli_config)
        
        # Run scanner asynchronously
        results = asyncio.run(run_scan(config_data))
        
        # Prepare results with absolute paths
        if results:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            app_dir = get_app_dir()
            reports_dir = app_dir / 'reports'
            reports_dir.mkdir(exist_ok=True)
            
            if args.output:
                output_file = Path(args.output).resolve()
            else:
                output_file = reports_dir / f"scan_report_{timestamp}.{args.format}"
            
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Pass results directly to report generator
            generate_report(
                scan_results=results,
                output_format=args.format,
                output_file=str(output_file)
            )
            
            logging.info(f"Report saved to: {output_file}")
            return 0
        return 1

    except Exception as e:
        logging.error(f"Scan failed: {str(e)}", exc_info=args.verbose)
        return 1

if __name__ == "__main__":
    sys.exit(run_scanner())
