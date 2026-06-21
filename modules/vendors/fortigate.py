from __future__ import annotations

from typing import Any

from modules.vendors.base_vendor import BaseFirewallVendor


class FortiGateConnector(BaseFirewallVendor):
    def collect(self) -> dict[str, Any]:
        token = self.env("api_token_env")
        headers = self.base_headers()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        base_url = f"https://{self.config.get('management_ip')}"
        payload: dict[str, Any] = {
            "vendor": "fortigate",
            "status": "placeholder",
            "requests": [],
        }

        if token:
            payload["requests"].append(
                {
                    "endpoint": f"{base_url}/api/v2/cmdb/firewall/policy",
                    "method": "GET",
                    "headers": {key: ("***" if key == "Authorization" else value) for key, value in headers.items()},
                    "note": "Conector base preparado para recuperar politicas via API token.",
                }
            )
        else:
            payload["warning"] = "Variable de entorno del token no configurada; se genera estructura base sin consulta remota."

        self.write_evidence("raw", payload)
        rules = [
            {
                "name": "FortiGate-Example-Allow-Any-Admin",
                "source": "any",
                "destination": ["mgmt-interface"],
                "service": ["https-admin"],
                "action": "allow",
                "logging": False,
                "nat": {"type": "none"},
                "vpn": {"enabled": False, "mfa": False},
            }
        ]
        return self.normalized(rules, metadata={"collector": "FortiGate API token base"})
