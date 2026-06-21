from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class CheckPointConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {
            "vendor": "checkpoint",
            "status": "extensible",
            "note": "Preparado para integrar Management API autenticada con variables de entorno.",
        }
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "Check Point scaffold"})
