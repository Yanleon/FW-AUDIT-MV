from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class CiscoConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {
            "vendor": "cisco_asa_ftd_fmc",
            "status": "extensible",
            "note": "Pensado para ASA/FTD/FMC segun el origen de configuracion autorizado.",
        }
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "Cisco scaffold"})
