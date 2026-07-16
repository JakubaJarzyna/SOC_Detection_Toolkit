import json
from pathlib import Path

from soc_detection_toolkit.models import IOCResults


def save_json_report(results: IOCResults, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)
