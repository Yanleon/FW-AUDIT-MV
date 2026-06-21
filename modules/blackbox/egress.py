from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any


class EgressTester:
    def __init__(self, evidence_dir: Path, scope: dict[str, Any], config: dict[str, Any]) -> None:
        self.evidence_dir = evidence_dir
        self.scope = scope
        self.config = config

    def run_tests(self) -> list[dict[str, Any]]:
        host = self.config.get("controlled_external_ip")
        timeout = str(self.scope.get("default_timeout", 120))
        results = []
        for port in self.config.get("test_ports", []):
            results.append(self._test_port(host, int(port), timeout))
        evidence_path = self.evidence_dir / "egress_results.json"
        evidence_path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        return results

    def _test_port(self, host: str, port: int, timeout: str) -> dict[str, Any]:
        nc_path = shutil.which("nc")
        if nc_path:
            cmd = [nc_path, "-vz", "-w", timeout, host, str(port)]
            result = subprocess.run(cmd, capture_output=True, text=True, shell=False)
            return {
                "host": host,
                "port": port,
                "status": "reachable" if result.returncode == 0 else "blocked_or_filtered",
                "command": cmd,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        try:
            with socket.create_connection((host, port), timeout=min(int(timeout), 5)):
                status = "reachable"
        except OSError:
            status = "blocked_or_filtered"
        return {"host": host, "port": port, "status": status, "command": ["python-socket"]}
