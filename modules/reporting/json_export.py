from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JSONExporter:
    def build(self, dataset: dict[str, Any], output_path: Path) -> None:
        output_path.write_text(json.dumps(dataset, indent=2, ensure_ascii=False), encoding="utf-8")
