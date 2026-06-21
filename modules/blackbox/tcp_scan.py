from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


class TCPScanner:
    def __init__(self, evidence_dir: Path, scope: dict[str, Any], config: dict[str, Any]) -> None:
        self.evidence_dir = evidence_dir
        self.scope = scope
        self.config = config

    def scan_target(self, target: str) -> dict[str, Any]:
        ports = self.config.get("tcp_ports", "1-1000")
        xml_path = self.evidence_dir / f"tcp_scan_{target.replace('.', '_')}.xml"
        cmd = ["nmap", "-sS", "-Pn", "-n", "-p", str(ports), "--max-retries", "2", "--host-timeout", f"{self.scope.get('default_timeout', 120)}s"]
        if self.config.get("service_detection", True):
            cmd.append("-sV")
        cmd.extend(["-oX", str(xml_path), target])
        return self._execute("tcp", target, cmd, xml_path)

    def _execute(self, scan_type: str, target: str, cmd: list[str], xml_path: Path) -> dict[str, Any]:
        tool = shutil.which(cmd[0])
        if not tool:
            return self._fallback(scan_type, target, cmd, xml_path, "nmap no esta instalado")
        cmd[0] = tool
        result = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=self.scope.get("default_timeout", 120) + 30)
        payload = {
            "type": scan_type,
            "target": target,
            "command": cmd,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "xml_path": str(xml_path),
        }
        json_path = self.evidence_dir / f"{scan_type}_scan_{target.replace('.', '_')}.json"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return payload

    def _fallback(self, scan_type: str, target: str, cmd: list[str], xml_path: Path, reason: str) -> dict[str, Any]:
        xml_path.write_text("<scan status=\"skipped\" />\n", encoding="utf-8")
        payload = {
            "type": scan_type,
            "target": target,
            "command": cmd,
            "returncode": None,
            "stdout": "",
            "stderr": reason,
            "xml_path": str(xml_path),
            "status": "skipped",
        }
        json_path = self.evidence_dir / f"{scan_type}_scan_{target.replace('.', '_')}.json"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return payload
