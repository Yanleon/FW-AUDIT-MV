from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class SonicWallConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {"vendor": "sonicwall", "status": "extensible", "note": "Scaffold para integracion futura por API o export autorizado."}
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "SonicWall scaffold"})
