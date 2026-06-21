from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class WatchGuardConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {"vendor": "watchguard", "status": "extensible", "note": "Scaffold para WatchGuard Cloud o Fireware segun autorizacion."}
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "WatchGuard scaffold"})
