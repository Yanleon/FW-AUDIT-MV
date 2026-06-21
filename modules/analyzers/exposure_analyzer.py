from __future__ import annotations

from typing import Any


class ExposureAnalyzer:
    def analyze(self, blackbox: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        blocked_ports = set(config.get("blackbox", {}).get("blocked_public_ports", []))
        allowed_ports = set(config.get("blackbox", {}).get("allowed_public_ports", []))

        for tcp_result in blackbox.get("tcp", []):
            stdout = tcp_result.get("stdout", "")
            target = tcp_result.get("target", "desconocido")
            for port in blocked_ports:
                token = f"{port}/tcp open"
                if token in stdout:
                    findings.append(
                        {
                            "title": f"Puerto publico bloqueado expuesto en {target}",
                            "severity": "High",
                            "category": "Exposure",
                            "description": f"El puerto {port}/tcp deberia estar bloqueado pero aparecio abierto.",
                            "recommendation": "Revisar reglas de publicacion, NAT y objetos de servicio.",
                            "evidence": tcp_result,
                        }
                    )
            for port in allowed_ports:
                token = f"{port}/tcp open"
                if token not in stdout:
                    findings.append(
                        {
                            "title": f"Puerto permitido no observable en {target}",
                            "severity": "Low",
                            "category": "Exposure",
                            "description": f"El puerto {port}/tcp esperado no fue observado durante la validacion externa.",
                            "recommendation": "Validar rutas, VIPs, listeners y estado del servicio publicado.",
                            "evidence": tcp_result,
                        }
                    )

        for check in blackbox.get("segmentation", []):
            for item in check.get("blocked_checks", []):
                if item.get("status") == "reachable":
                    findings.append(
                        {
                            "title": f"Segmentacion interna debil hacia {check.get('name')}",
                            "severity": "High",
                            "category": "Segmentation",
                            "description": f"El puerto {item['port']} respondio aunque deberia estar bloqueado.",
                            "recommendation": "Reforzar politicas inter-zona y listas de control internas.",
                            "evidence": item,
                        }
                    )

        for item in blackbox.get("egress", []):
            if item.get("status") == "reachable" and item.get("port") in {21, 23, 25, 445, 3389}:
                findings.append(
                    {
                        "title": f"Egress permisivo hacia {item['host']}:{item['port']}",
                        "severity": "Medium",
                        "category": "Egress",
                        "description": "Se observo salida hacia un puerto que normalmente requiere control estricto.",
                        "recommendation": "Aplicar filtrado saliente basado en minimo privilegio.",
                        "evidence": item,
                    }
                )

        return findings
