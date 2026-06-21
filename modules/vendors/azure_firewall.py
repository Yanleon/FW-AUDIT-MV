from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class AzureFirewallConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {"vendor": "azure_firewall", "status": "extensible", "note": "Scaffold para Azure SDK o exportes JSON autorizados."}
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "Azure Firewall scaffold"})
