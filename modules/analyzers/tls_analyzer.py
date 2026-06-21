from __future__ import annotations

from typing import Any


class TLSAnalyzer:
    def analyze(self, blackbox: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        weak_markers = {
            "TLSv1.0": "Medium",
            "TLSv1.1": "Medium",
            "3DES": "High",
            "RC4": "High",
            "NULL": "Critical",
        }
        for result in blackbox.get("tls", []):
            stdout = result.get("stdout", "")
            for marker, severity in weak_markers.items():
                if marker in stdout:
                    findings.append(
                        {
                            "title": f"Parametro TLS debil detectado: {marker}",
                            "severity": severity,
                            "category": "TLS",
                            "description": f"La enumeracion TLS mostro compatibilidad con {marker}.",
                            "recommendation": "Restringir protocolos y suites criptograficas obsoletas.",
                            "evidence": result,
                        }
                    )
        return findings
