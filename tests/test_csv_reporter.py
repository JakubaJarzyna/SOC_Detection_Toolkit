import csv
from pathlib import Path

from soc_detection_toolkit.csv_reporter import save_csv_report
from soc_detection_toolkit.models import IOCResults


def test_save_csv_report(tmp_path: Path) -> None:
    output_file = tmp_path / "report.csv"

    results: IOCResults = {
        "ips": ["192.168.1.10"],
        "urls": ["https://example.com"],
        "domains": ["example.org"],
        "hashes": [],
        "emails": ["soc@example.org"],
        "unknown": [],
    }

    save_csv_report(results, str(output_file))

    with output_file.open(encoding="utf-8", newline="") as file:
        rows = list(csv.reader(file))

    assert rows == [
        ["type", "value"],
        ["ips", "192.168.1.10"],
        ["urls", "https://example.com"],
        ["domains", "example.org"],
        ["emails", "soc@example.org"],
    ]


def test_save_csv_report_creates_parent_directories(tmp_path: Path) -> None:
    output_file = tmp_path / "nested" / "reports" / "report.csv"

    results: IOCResults = {
        "ips": [],
        "urls": [],
        "domains": [],
        "hashes": [],
        "emails": [],
        "unknown": [],
    }

    save_csv_report(results, str(output_file))

    assert output_file.exists()