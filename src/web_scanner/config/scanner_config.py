"""
scanner_config.py — YAML config loader for the web scanner.

This module is intentionally small:
  - ScannerConfig (the config shape) lives in web_scanner.types — one source of truth.
  - load_scanner_config() reads a YAML file and returns a ready-to-use ScannerConfig.
"""

import logging
from pathlib import Path

import yaml

# Re-export ScannerConfig so that existing imports like
#   from web_scanner.config.scanner_config import ScannerConfig
# continue to work without changes.
from ..types import ScannerConfig

__all__ = ["ScannerConfig", "load_scanner_config"]


def load_scanner_config(path: str) -> ScannerConfig:
    """Load a YAML config file and return a ScannerConfig.

    Unknown YAML keys are logged as warnings and skipped — no crash.
    The modules section can be a list (recommended) or a legacy dict with
    enabled flags; both are normalized by ScannerConfig.
    """
    config_path = Path(path).resolve()
    with config_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    cfg = ScannerConfig()
    cfg.update(data)   # update() in ScannerConfig skips unknown keys safely
    logging.debug("Loaded config from %s", config_path)
    return cfg
