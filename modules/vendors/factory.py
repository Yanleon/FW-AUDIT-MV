from __future__ import annotations

from pathlib import Path

from modules.vendors.aws_network_firewall import AWSNetworkFirewallConnector
from modules.vendors.azure_firewall import AzureFirewallConnector
from modules.vendors.checkpoint import CheckPointConnector
from modules.vendors.cisco_asa_ftd import CiscoConnector
from modules.vendors.fortigate import FortiGateConnector
from modules.vendors.juniper_srx import JuniperSRXConnector
from modules.vendors.paloalto import PaloAltoConnector
from modules.vendors.sonicwall import SonicWallConnector
from modules.vendors.sophos import SophosConnector
from modules.vendors.watchguard import WatchGuardConnector


class VendorFactory:
    REGISTRY = {
        "fortigate": FortiGateConnector,
        "paloalto": PaloAltoConnector,
        "checkpoint": CheckPointConnector,
        "cisco_asa_ftd": CiscoConnector,
        "cisco": CiscoConnector,
        "sophos": SophosConnector,
        "sonicwall": SonicWallConnector,
        "watchguard": WatchGuardConnector,
        "juniper_srx": JuniperSRXConnector,
        "aws_network_firewall": AWSNetworkFirewallConnector,
        "azure_firewall": AzureFirewallConnector,
    }

    @classmethod
    def create(cls, config: dict, evidence_dir: Path):
        vendor = str(config.get("vendor", "")).lower()
        connector_cls = cls.REGISTRY.get(vendor)
        if not connector_cls:
            raise ValueError(f"Vendor no soportado: {vendor}")
        return connector_cls(config, evidence_dir)
