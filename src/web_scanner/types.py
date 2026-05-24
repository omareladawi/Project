from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List
import logging


@dataclass
class ScannerConfig:
    """Runtime configuration for the scanner."""

    target_url: str = ""
    timeout: int = 10
    user_agent: str = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    verify_ssl: bool = True
    modules: List[str] = field(default_factory=lambda: ["recon"])
    active_tests: bool = True  # Enable active tests by default for comprehensive scanning
    crawl_depth: int = 3  # Increased depth for more thorough discovery
    auth_enabled: bool = False
    auth_url: str = ""
    auth_user: str = ""
    auth_pass: str = ""
    auth_username_field: str = "username"
    auth_password_field: str = "password"
    result_deduplication: bool = True
    max_pages: int = 50
    max_active_tests: int = 50
    max_page_concurrency: int = 4

    # Optional external findings provider (Claude Security)
    claude_security_enabled: bool = False
    claude_security_url: str = ""
    claude_security_api_key: str = ""
    claude_security_timeout: int = 20
    claude_security_include_local_findings: bool = True

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
        if isinstance(value, (list, tuple)):
            return list(value)
        return []

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)