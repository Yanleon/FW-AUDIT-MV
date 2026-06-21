from __future__ import annotations

from typing import Any


class RuleAnalyzer:
    def analyze(self, normalized_config: dict[str, Any]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        device = normalized_config.get("device", {})
        for rule in normalized_config.get("rules", []):
            if self._is_any_any(rule):
                findings.append(self._finding(device, rule, "Critical", "Regla any-any detectada", "Limitar origen, destino y servicio al minimo necesario."))
            if not rule.get("logging", False):
                findings.append(self._finding(device, rule, "Medium", "Regla sin logging", "Habilitar registro para trazabilidad y respuesta a incidentes."))
            if rule.get("nat", {}).get("type") in {"dynamic-any", "full-cone"}:
                findings.append(self._finding(device, rule, "High", "NAT riesgoso", "Revisar alcance de NAT y limitar exposicion no requerida."))
            if rule.get("vpn", {}).get("enabled") and not rule.get("vpn", {}).get("mfa", False):
                findings.append(self._finding(device, rule, "High", "VPN sin MFA", "Exigir MFA para accesos remotos administrativos o de usuarios."))
            if self._admin_from_any(rule):
                findings.append(self._finding(device, rule, "Critical", "Administracion permitida desde any", "Restringir gestion a redes de administracion dedicadas."))

        return {"device": device, "findings": findings}

    def _is_any_any(self, rule: dict[str, Any]) -> bool:
        return self._is_any(rule.get("source")) and self._is_any(rule.get("destination")) and self._is_any(rule.get("service"))

    def _admin_from_any(self, rule: dict[str, Any]) -> bool:
        admin_services = {"https-admin", "ssh-admin", "mgmt", "admin"}
        service = rule.get("service")
        services = service if isinstance(service, list) else [service]
        return self._is_any(rule.get("source")) and any(item in admin_services for item in services)

    def _is_any(self, value: Any) -> bool:
        if value == "any":
            return True
        if isinstance(value, list):
            return len(value) == 1 and value[0] == "any"
        return False

    def _finding(self, device: dict[str, Any], rule: dict[str, Any], severity: str, title: str, recommendation: str) -> dict[str, Any]:
        return {
            "title": title,
            "severity": severity,
            "category": "Policy",
            "description": f"La regla {rule.get('name', 'sin_nombre')} del dispositivo {device.get('name', 'desconocido')} requiere revision.",
            "recommendation": recommendation,
            "evidence": {"device": device, "rule": rule},
        }
