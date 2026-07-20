import json
from datetime import UTC, datetime
from pathlib import Path

from soc_detection_toolkit.models import IOCCounts, IOCReport, IOCResults


def count_indicators(results: IOCResults) -> int:
    return (
        len(results["ips"])
        + len(results["urls"])
        + len(results["domains"])
        + len(results["hashes"])
        + len(results["emails"])
        + len(results["unknown"])
    )


def build_report(results: IOCResults, source_file: str) -> IOCReport:
    counts: IOCCounts = {
        "ips": len(results["ips"]),
        "urls": len(results["urls"]),
        "domains": len(results["domains"]),
        "hashes": len(results["hashes"]),
        "emails": len(results["emails"]),
        "unknown": len(results["unknown"]),
    }

    report: IOCReport = {
        "metadata": {
            "generated_at": datetime.now(UTC).isoformat(),
            "source_file": source_file,
            "total_items": count_indicators(results),
            "counts": counts,
        },
        "indicators": results,
    }

    return report


def save_json_report(report: IOCReport, output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)
        file.write("\n")
