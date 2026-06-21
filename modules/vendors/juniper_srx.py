from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class JuniperSRXConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {"vendor": "juniper_srx", "status": "extensible", "note": "Scaffold preparado para integrar NETCONF, SSH o API segun entorno."}
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "Juniper SRX scaffold"})
