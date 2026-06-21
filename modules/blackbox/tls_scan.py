from __future__ import annotations

from pathlib import Path
from typing import Any

from modules.blackbox.tcp_scan import TCPScanner


class TLSScanner(TCPScanner):
    def __init__(self, evidence_dir: Path, scope: dict[str, Any], config: dict[str, Any]) -> None:
        super().__init__(evidence_dir, scope, config)

    def scan_target(self, target: str) -> dict[str, Any]:
        ports = ",".join(str(port) for port in self.config.get("tls_ports", [443]))
        xml_path = self.evidence_dir / f"tls_scan_{target.replace('.', '_')}.xml"
        cmd = [
            "nmap",
            "-sV",
            "-Pn",
            "-n",
            "-p",
            ports,
            "--script",
            "ssl-enum-ciphers",
            "--host-timeout",
            f"{self.scope.get('default_timeout', 120)}s",
            "-oX",
            str(xml_path),
            target,
        ]
        return self._execute("tls", target, cmd, xml_path)
