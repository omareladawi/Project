# =========================
# Scanner Configuration
# =========================

import logging
import yaml

from pathlib import Path
from ..types import ScannerConfig



def load_scanner_config(path: str):

    config_path = Path(path).resolve()
    with config_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    cfg = ScannerConfig()
    cfg.update(data)  
    logging.debug("Loaded config from %s", config_path)
    return cfg
