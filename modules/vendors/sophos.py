from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class SophosConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {"vendor": "sophos", "status": "extensible", "note": "Scaffold para integracion futura por API."}
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "Sophos scaffold"})
