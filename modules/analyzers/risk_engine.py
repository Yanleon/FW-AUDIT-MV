from __future__ import annotations

from typing import Any


class RiskEngine:
    def build_results(
        self,
        exposure_findings: list[dict[str, Any]],
        tls_findings: list[dict[str, Any]],
        rule_analysis: list[dict[str, Any]],
    ) -> dict[str, Any]:
        findings = list(exposure_findings) + list(tls_findings)
        for item in rule_analysis:
            findings.extend(item.get("findings", []))

        summary = {severity: 0 for severity in ("Critical", "High", "Medium", "Low", "Informational")}
        for finding in findings:
            severity = finding.get("severity", "Informational")
            summary[severity] = summary.get(severity, 0) + 1

        recommendations = []
        seen = set()
        for finding in findings:
            rec = finding.get("recommendation")
            if rec and rec not in seen:
                seen.add(rec)
                recommendations.append(rec)

        return {
            "summary": summary,
            "findings": findings,
            "recommendations": recommendations,
        }
