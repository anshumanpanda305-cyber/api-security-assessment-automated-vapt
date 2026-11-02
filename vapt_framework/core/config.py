import os
import yaml
from typing import Dict, Any, Optional

DEFAULT_CONFIG = {
    "target": {
        "base_url": "http://127.0.0.1:5000",
        "authorized_hosts": ["127.0.0.1", "localhost", "::1"]
    },
    "proxy": {
        "enabled": False,
        "url": "http://127.0.0.1:8080"
    },
    "test_accounts": {
        "alice": {
            "username": "alice",
            "password": "Password123!",
            "role": "user",
            "id": 1
        },
        "bob": {
            "username": "bob",
            "password": "Password123!",
            "role": "user",
            "id": 2
        },
        "admin": {
            "username": "admin",
            "password": "AdminSecurePass!",
            "role": "admin",
            "id": 4
        }
    },
    "scanner": {
        "timeout": 8,
        "max_threads": 4,
        "output_dir": "reports",
        "wordlists_dir": "vapt_framework/wordlists"
    }
}

class FrameworkConfig:
    """Manages VAPT framework configuration."""
    def __init__(self, config_path: Optional[str] = None):
        self.data = dict(DEFAULT_CONFIG)
        if config_path and os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                user_conf = yaml.safe_load(f) or {}
                self._deep_update(self.data, user_conf)

    def _deep_update(self, base: dict, update: dict):
        for k, v in update.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                self._deep_update(base[k], v)
            else:
                base[k] = v

    def get(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split(".")
        val = self.data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val
