from __future__ import annotations

from modules.vendors.base_vendor import BaseFirewallVendor


class AWSNetworkFirewallConnector(BaseFirewallVendor):
    def collect(self) -> dict:
        payload = {"vendor": "aws_network_firewall", "status": "extensible", "note": "Scaffold para integrar boto3 cuando se requiera en entornos AWS."}
        self.write_evidence("raw", payload)
        return self.normalized(self.placeholder_rules(), metadata={"collector": "AWS Network Firewall scaffold"})
