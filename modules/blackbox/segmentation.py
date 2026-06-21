from __future__ import annotations

import json
import shutil
import socket
from pathlib import Path
from typing import Any


class SegmentationTester:
    def __init__(self, evidence_dir: Path, scope: dict[str, Any], config: dict[str, Any]) -> None:
        self.evidence_dir = evidence_dir
        self.scope = scope
        self.config = config

    def test_target(self, target: dict[str, Any]) -> dict[str, Any]:
        timeout = self.scope.get("default_timeout", 120)
        allowed = [self._probe_port(target["ip"], port, timeout) for port in target.get("allowed_ports", [])]
        blocked = [self._probe_port(target["ip"], port, timeout) for port in target.get("blocked_ports", [])]
        payload = {
            "name": target.get("name"),
            "ip": target.get("ip"),
            "allowed_checks": allowed,
            "blocked_checks": blocked,
            "tooling": {"socket": shutil.which("nc") or "python-socket"},
        }
        evidence_path = self.evidence_dir / f"segmentation_{target['ip'].replace('.', '_')}.json"
        evidence_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return payload

    def _probe_port(self, host: str, port: int, timeout: int) -> dict[str, Any]:
        status = "blocked"
        try:
            with socket.create_connection((host, port), timeout=min(timeout, 5)):
                status = "reachable"
        except OSError:
            status = "blocked_or_filtered"
        return {"host": host, "port": port, "status": status}
