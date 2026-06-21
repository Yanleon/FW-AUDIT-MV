from __future__ import annotations

from pathlib import Path
from typing import Any


class MarkdownReportBuilder:
    def build(self, dataset: dict[str, Any], output_path: Path) -> None:
        findings = dataset.get("findings", {}).get("findings", [])
        summary = dataset.get("findings", {}).get("summary", {})
        lines = [
            f"# {dataset['metadata']['project'].get('name', 'FW-AUDIT-MV')}",
            "",
            "## Resumen Ejecutivo",
            f"- Cliente: {dataset['metadata']['project'].get('client', 'N/D')}",
            f"- Tester: {dataset['metadata']['project'].get('tester', 'N/D')}",
            f"- Entorno: {dataset['metadata']['project'].get('environment', 'N/D')}",
            f"- Autorizacion: {dataset['metadata']['project'].get('authorization_id', 'N/D')}",
            f"- Timestamp: {dataset['metadata'].get('timestamp', 'N/D')}",
            "",
            "## Resumen por Severidad",
        ]
        for severity in ("Critical", "High", "Medium", "Low", "Informational"):
            lines.append(f"- {severity}: {summary.get(severity, 0)}")

        lines.extend([
            "",
            "## Tabla de Hallazgos",
            "| Severidad | Categoria | Titulo |",
            "| --- | --- | --- |",
        ])
        for finding in findings:
            lines.append(f"| {finding.get('severity')} | {finding.get('category')} | {finding.get('title')} |")

        lines.extend(["", "## Hallazgos Detallados"])
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.get('title')}",
                    f"- Severidad: {finding.get('severity')}",
                    f"- Categoria: {finding.get('category')}",
                    f"- Descripcion: {finding.get('description')}",
                    f"- Recomendacion: {finding.get('recommendation')}",
                    "",
                ]
            )

        lines.extend(["## Evidencias", f"- Carpeta de evidencia: `{dataset.get('evidence_dir')}`", "", "## Recomendaciones"])
        for item in dataset.get("findings", {}).get("recommendations", []):
            lines.append(f"- {item}")

        lines.extend([
            "",
            "## Anexo Tecnico",
            "- Caja negra: resultados de TCP, UDP, TLS, segmentacion y egress.",
            "- Caja blanca: configuracion normalizada por fabricante y analisis de reglas.",
        ])
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
