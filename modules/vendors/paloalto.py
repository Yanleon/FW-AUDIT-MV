from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class PaloAltoConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {
            "vendor": "paloalto",
            "status": "extensible",
            "note": "Agregar logica XML API o REST API segun el despliegue administrado.",
        }
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "Palo Alto scaffold"})
