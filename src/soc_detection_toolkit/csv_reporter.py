import csv
from pathlib import Path
from typing import Literal

from soc_detection_toolkit.models import IOCResults

IOCType = Literal[
    "ips",
    "urls",
    "domains",
    "hashes",
    "emails",
    "unknown",
]


def save_csv_report(results: IOCResults, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    indicator_types: tuple[IOCType, ...] = (
        "ips",
        "urls",
        "domains",
        "hashes",
        "emails",
        "unknown",
    )

    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["type", "value"])

        for indicator_type in indicator_types:
            for value in results[indicator_type]:
                writer.writerow([indicator_type, value])
