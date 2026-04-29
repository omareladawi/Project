from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List
import logging


@dataclass
class ScannerConfig:
    """Runtime configuration for the scanner."""

    target_url: str = ""
    timeout: int = 10
    user_agent: str = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    verify_ssl: bool = False
    modules: List[str] = field(default_factory=lambda: ["recon"])
    active_tests: bool = False
    result_deduplication: bool = True

    def update(self, updates: Dict[str, Any]) -> None:
        """Apply overrides safely and skip unknown keys."""
        for key, value in updates.items():
            if key == "modules":
                self.modules = self._normalize_modules(value)
                continue

            if hasattr(self, key):
                setattr(self, key, value)
            else:
                logging.warning("Ignoring unknown config key: %s", key)

    @staticmethod
    def _normalize_modules(value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            enabled = []
            for name, config in value.items():
                if isinstance(config, dict):
                    is_enabled = bool(config.get("enabled"))
                else:
                    is_enabled = bool(config)
                if is_enabled:
                    enabled.append(name)
            return enabled
        if isinstance(value, list):
            return [str(item) for item in value if item]
        return []

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScannerConfig":
        cfg = cls()
        cfg.update(data)
        return cfg

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
