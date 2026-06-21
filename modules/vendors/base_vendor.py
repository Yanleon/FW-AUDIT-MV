from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import requests


class BaseFirewallVendor(ABC):
    def __init__(self, config: dict[str, Any], evidence_dir: Path) -> None:
        self.config = config
        self.evidence_dir = evidence_dir
        self.logger = logging.getLogger(self.__class__.__name__)
        self.session = requests.Session()
        self.session.verify = bool(config.get("verify_ssl", True))
        self.slug = f"{config.get('vendor', 'vendor')}_{config.get('name', 'device').lower().replace(' ', '_')}"

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        raise NotImplementedError

    def env(self, key_name: str) -> str:
        env_key = self.config.get(key_name)
        if not env_key:
            return ""
        return os.getenv(env_key, "")

    def base_headers(self) -> dict[str, str]:
        return {"User-Agent": "fw-audit-mv/1.0", "Accept": "application/json"}

    def write_evidence(self, suffix: str, payload: dict[str, Any]) -> Path:
        evidence_path = self.evidence_dir / f"{self.slug}_{suffix}.json"
        evidence_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return evidence_path

    def normalized(self, rules: list[dict[str, Any]], objects: dict[str, Any] | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "device": {
                "name": self.config.get("name"),
                "vendor": self.config.get("vendor"),
                "management_ip": self.config.get("management_ip"),
                "auth_method": self.config.get("auth_method"),
            },
            "metadata": metadata or {},
            "objects": objects or {},
            "rules": rules,
        }

    def placeholder_rules(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "placeholder-review-rule",
                "source": "any",
                "destination": ["management-zone"],
                "service": ["https-admin"],
                "action": "allow",
                "logging": False,
                "nat": {"type": "none"},
                "vpn": {"enabled": False, "mfa": False},
            }
        ]
