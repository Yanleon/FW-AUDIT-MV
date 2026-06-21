from __future__ import annotations

from pathlib import Path
from typing import Any

from modules.blackbox.tcp_scan import TCPScanner


class UDPScanner(TCPScanner):
    def __init__(self, evidence_dir: Path, scope: dict[str, Any], config: dict[str, Any]) -> None:
        super().__init__(evidence_dir, scope, config)

    def scan_target(self, target: str) -> dict[str, Any]:
        top_ports = str(self.config.get("udp_top_ports", 50))
        xml_path = self.evidence_dir / f"udp_scan_{target.replace('.', '_')}.xml"
        cmd = [
            "nmap",
            "-sU",
            "-Pn",
            "-n",
            "--top-ports",
            top_ports,
            "--max-retries",
            "1",
            "--host-timeout",
            f"{self.scope.get('default_timeout', 120)}s",
            "-oX",
            str(xml_path),
            target,
        ]
        return self._execute("udp", target, cmd, xml_path)
