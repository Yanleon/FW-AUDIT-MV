#!/usr/bin/env python3
"""CLI principal para FW-AUDIT-MV."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console
from rich.table import Table

from modules.analyzers.exposure_analyzer import ExposureAnalyzer
from modules.analyzers.risk_engine import RiskEngine
from modules.analyzers.rule_analyzer import RuleAnalyzer
from modules.analyzers.tls_analyzer import TLSAnalyzer
from modules.blackbox.egress import EgressTester
from modules.blackbox.segmentation import SegmentationTester
from modules.blackbox.tcp_scan import TCPScanner
from modules.blackbox.tls_scan import TLSScanner
from modules.blackbox.udp_scan import UDPScanner
from modules.reporting.html_report import HTMLReportBuilder
from modules.reporting.json_export import JSONExporter
from modules.reporting.markdown_report import MarkdownReportBuilder
from modules.vendors.factory import VendorFactory

APP_NAME = "FW-AUDIT-MV"
SUPPORTED_MODES = {"full", "blackbox", "whitebox", "external", "internal", "tls", "egress", "report"}
console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Herramienta CLI para auditoria autorizada de firewalls multi-vendor."
    )
    parser.add_argument("--config", required=True, help="Ruta al archivo YAML de configuracion.")
    parser.add_argument("--mode", required=True, choices=sorted(SUPPORTED_MODES), help="Modo de ejecucion.")
    return parser.parse_args()


def load_env_file(env_path: Path) -> None:
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_config(config_path: Path) -> dict[str, Any]:
    with config_path.open("r", encoding="utf-8") as handler:
        return yaml.safe_load(handler) or {}


def latest_evidence_dir(base_path: Path) -> Path | None:
    evidence_dir = base_path / "evidence"
    if not evidence_dir.exists():
        return None
    candidates = [item for item in evidence_dir.iterdir() if item.is_dir()]
    if not candidates:
        return None
    return sorted(candidates)[-1]


def ensure_runtime_dirs(base_path: Path, mode: str) -> dict[str, Path]:
    evidence_dir = base_path / "evidence"
    reports_dir = base_path / "reports"
    logs_dir = base_path / "logs"
    for directory in (evidence_dir, reports_dir, logs_dir):
        directory.mkdir(parents=True, exist_ok=True)

    if mode == "report":
        existing = latest_evidence_dir(base_path)
        if existing is not None:
            timestamp = existing.name
            run_evidence_dir = existing
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_evidence_dir = evidence_dir / timestamp
            run_evidence_dir.mkdir(parents=True, exist_ok=True)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_evidence_dir = evidence_dir / timestamp
        run_evidence_dir.mkdir(parents=True, exist_ok=True)

    return {
        "base": base_path,
        "evidence": evidence_dir,
        "run_evidence": run_evidence_dir,
        "reports": reports_dir,
        "logs": logs_dir,
        "timestamp": Path(timestamp),
    }


def configure_logging(logs_dir: Path, timestamp: str) -> Path:
    log_file = logs_dir / f"fw_audit_{timestamp}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[logging.FileHandler(log_file, encoding="utf-8"), logging.StreamHandler(sys.stdout)],
    )
    return log_file


def safe_serialize(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: safe_serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [safe_serialize(item) for item in value]
    return value


def save_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(safe_serialize(payload), indent=2, ensure_ascii=False), encoding="utf-8")


def run_blackbox(config: dict[str, Any], runtime: dict[str, Path], mode: str) -> dict[str, Any]:
    logging.info("Iniciando pruebas de caja negra")
    scope = config.get("scope", {})
    blackbox_cfg = config.get("blackbox", {})
    internal_cfg = config.get("internal_tests", {})
    egress_cfg = config.get("egress", {})
    parallelism = max(1, min(scope.get("max_parallel_scans", 2), 4))

    tcp_scanner = TCPScanner(runtime["run_evidence"], scope, blackbox_cfg)
    udp_scanner = UDPScanner(runtime["run_evidence"], scope, blackbox_cfg)
    tls_scanner = TLSScanner(runtime["run_evidence"], scope, blackbox_cfg)
    segmentation = SegmentationTester(runtime["run_evidence"], scope, internal_cfg)
    egress = EgressTester(runtime["run_evidence"], scope, egress_cfg)

    tasks: list[tuple[str, Any]] = []
    targets = blackbox_cfg.get("public_ips", [])
    run_tcp = mode in {"full", "blackbox", "external", "internal"}
    run_udp = blackbox_cfg.get("udp_scan", False) and mode in {"full", "blackbox", "external"}
    run_tls = mode in {"full", "blackbox", "external", "tls"}
    run_segmentation = internal_cfg.get("enabled", False) and mode in {"full", "blackbox", "internal"}
    run_egress = egress_cfg.get("enabled", False) and mode in {"full", "blackbox", "egress"}

    for target in targets:
        if run_tcp:
            tasks.append((f"tcp_{target}", lambda target=target: tcp_scanner.scan_target(target)))
        if run_udp:
            tasks.append((f"udp_{target}", lambda target=target: udp_scanner.scan_target(target)))
        if run_tls:
            tasks.append((f"tls_{target}", lambda target=target: tls_scanner.scan_target(target)))

    results: dict[str, Any] = {"tcp": [], "udp": [], "tls": [], "segmentation": [], "egress": []}

    with ThreadPoolExecutor(max_workers=parallelism) as executor:
        future_map = {executor.submit(func): name for name, func in tasks}
        for future in as_completed(future_map):
            name = future_map[future]
            data = future.result()
            if name.startswith("tcp_"):
                results["tcp"].append(data)
            elif name.startswith("udp_"):
                results["udp"].append(data)
            else:
                results["tls"].append(data)

    if run_segmentation:
        for target in internal_cfg.get("targets", []):
            results["segmentation"].append(segmentation.test_target(target))

    if run_egress:
        results["egress"] = egress.run_tests()

    save_json(runtime["run_evidence"] / "blackbox_summary.json", results)
    return results


def run_whitebox(config: dict[str, Any], runtime: dict[str, Path]) -> dict[str, Any]:
    logging.info("Iniciando pruebas de caja blanca")
    normalized_devices: list[dict[str, Any]] = []
    rule_results: list[dict[str, Any]] = []

    for vendor_cfg in config.get("vendors", []):
        if not vendor_cfg.get("enabled", False):
            continue
        connector = VendorFactory.create(vendor_cfg, runtime["run_evidence"])
        normalized = connector.collect()
        normalized_devices.append(normalized)
        save_json(runtime["run_evidence"] / f"{connector.slug}_normalized.json", normalized)
        rule_results.append(RuleAnalyzer().analyze(normalized))

    output = {"devices": normalized_devices, "rule_analysis": rule_results}
    save_json(runtime["run_evidence"] / "whitebox_summary.json", output)
    return output


def build_findings(config: dict[str, Any], blackbox: dict[str, Any], whitebox: dict[str, Any]) -> dict[str, Any]:
    exposure = ExposureAnalyzer().analyze(blackbox, config)
    tls = TLSAnalyzer().analyze(blackbox)
    rule_analysis = whitebox.get("rule_analysis", [])
    risk_engine = RiskEngine()
    return risk_engine.build_results(exposure, tls, rule_analysis)


def generate_reports(
    config: dict[str, Any],
    runtime: dict[str, Path],
    blackbox: dict[str, Any],
    whitebox: dict[str, Any],
    findings: dict[str, Any],
) -> dict[str, str]:
    timestamp = runtime["timestamp"].name
    report_base = f"fw_audit_report_{timestamp}"
    results_base = f"fw_audit_results_{timestamp}.json"
    report_paths: dict[str, str] = {}
    reporting_cfg = config.get("reporting", {})
    dataset = {
        "metadata": {
            "project": config.get("project", {}),
            "scope": config.get("scope", {}),
            "timestamp": timestamp,
        },
        "blackbox": blackbox,
        "whitebox": whitebox,
        "findings": findings,
        "evidence_dir": str(runtime["run_evidence"]),
    }

    if reporting_cfg.get("markdown", True):
        md_path = runtime["reports"] / f"{report_base}.md"
        MarkdownReportBuilder().build(dataset, md_path)
        report_paths["markdown"] = str(md_path)

    if reporting_cfg.get("html", True):
        html_path = runtime["reports"] / f"{report_base}.html"
        HTMLReportBuilder(runtime["base"] / "templates" / "report_template.html").build(dataset, html_path)
        report_paths["html"] = str(html_path)

    if reporting_cfg.get("json", True):
        json_path = runtime["reports"] / results_base
        JSONExporter().build(dataset, json_path)
        report_paths["json"] = str(json_path)

    return report_paths


def print_summary(report_paths: dict[str, str], findings: dict[str, Any]) -> None:
    console.print(f"\n[bold green]{APP_NAME} Finalizado[/bold green]\n")
    console.print("[bold]Reportes generados:[/bold]")
    for path in report_paths.values():
        console.print(f"- {path}")

    summary = findings.get("summary", {})
    table = Table(title="Hallazgos")
    table.add_column("Severidad")
    table.add_column("Total", justify="right")
    for severity in ("Critical", "High", "Medium", "Low", "Informational"):
        table.add_row(severity, str(summary.get(severity, 0)))
    console.print(table)


def empty_sections() -> tuple[dict[str, Any], dict[str, Any]]:
    return ({"tcp": [], "udp": [], "tls": [], "segmentation": [], "egress": []}, {"devices": [], "rule_analysis": []})


def main() -> int:
    args = parse_args()
    base_path = Path(__file__).resolve().parent
    load_env_file(base_path / ".env")
    config = load_config(Path(args.config).resolve())
    runtime = ensure_runtime_dirs(base_path, args.mode)
    timestamp = runtime["timestamp"].name
    log_file = configure_logging(runtime["logs"], timestamp)
    logging.info("Log de ejecucion: %s", log_file)

    safe_mode = bool(config.get("scope", {}).get("safe_mode", True))
    if not safe_mode:
        logging.warning("safe_mode=false: el operador debe validar la autorizacion del alcance.")

    blackbox_results, whitebox_results = empty_sections()

    if args.mode in {"full", "blackbox", "external", "internal", "tls", "egress"}:
        blackbox_results = run_blackbox(config, runtime, args.mode)
    if args.mode in {"full", "whitebox"}:
        whitebox_results = run_whitebox(config, runtime)

    if args.mode == "report":
        blackbox_path = runtime["run_evidence"] / "blackbox_summary.json"
        whitebox_path = runtime["run_evidence"] / "whitebox_summary.json"
        if blackbox_path.exists():
            blackbox_results = json.loads(blackbox_path.read_text(encoding="utf-8"))
        if whitebox_path.exists():
            whitebox_results = json.loads(whitebox_path.read_text(encoding="utf-8"))

    findings = build_findings(config, blackbox_results, whitebox_results)
    report_paths = generate_reports(config, runtime, blackbox_results, whitebox_results, findings)
    print_summary(report_paths, findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
