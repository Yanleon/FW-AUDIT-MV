from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


class HTMLReportBuilder:
    def __init__(self, template_path: Path) -> None:
        self.template_path = template_path

    def build(self, dataset: dict[str, Any], output_path: Path) -> None:
        env = Environment(
            loader=FileSystemLoader(str(self.template_path.parent)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template(self.template_path.name)
        output_path.write_text(template.render(dataset=dataset), encoding="utf-8")
