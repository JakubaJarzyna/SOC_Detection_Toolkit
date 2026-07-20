import json
from pathlib import Path

from soc_detection_toolkit.json_reporter import (
    build_report,
    count_indicators,
    save_json_report,
)
from soc_detection_toolkit.models import IOCResults

def test_count_indicators() -> None:
    results: IOCResults = {
        "ips": ["192.168.1.10"],
        "urls": ["https://example.com"],
        "domains": ["example.org"],
        "hashes": [],
        "emails": ["soc@example.org"],
        "unknown": ["invalid value"],
    }

    assert count_indicators(results) == 5

def test_build_report_contains_metadata() -> None:
    results: IOCResults = {
        "ips": ["192.168.1.10"],
        "urls": [],
        "domains": ["example.com"],
        "hashes": [],
        "emails": [],
        "unknown": [],
    }

    report = build_report(results, "data/iocs.txt")

    assert report["metadata"]["source_file"] == "data/iocs.txt"
    assert report["metadata"]["total_items"] == 2
    assert report["metadata"]["counts"]["ips"] == 1
    assert report["metadata"]["counts"]["domains"] == 1
    assert report["indicators"] == results
    assert report["metadata"]["generated_at"]


def test_save_json_report(tmp_path: Path) -> None:
    output_file = tmp_path / "report.json"

    results: IOCResults = {
        "ips": ["192.168.1.10"],
        "urls": ["https://example.com"],
        "domains": ["example.org"],
        "hashes": [],
        "emails": ["soc@example.org"],
        "unknown": [],
    }

    report = build_report(results, "data/iocs.txt")
    save_json_report(report, str(output_file))

    assert output_file.exists()

    saved_report = json.loads(output_file.read_text(encoding="utf-8"))

    assert saved_report == report


def test_create_parent_directories(tmp_path: Path) -> None:
    output_file = tmp_path / "nested" / "reports" / "report.json"

    results: IOCResults = {
        "ips": [],
        "urls": [],
        "domains": [],
        "hashes": [],
        "emails": [],
        "unknown": [],
    }

    report = build_report(results, "data/iocs.txt")
    save_json_report(report, str(output_file))

    assert output_file.exists()
    assert output_file.parent.is_dir()


def test_overwrite_existing_report(tmp_path: Path) -> None:
    output_file = tmp_path / "report.json"
    output_file.write_text('{"old": "content"}', encoding="utf-8")

    results: IOCResults = {
        "ips": ["10.0.0.1"],
        "urls": [],
        "domains": [],
        "hashes": [],
        "emails": [],
        "unknown": [],
    }

    report = build_report(results, "data/iocs.txt")
    save_json_report(report, str(output_file))

    saved_report = json.loads(output_file.read_text(encoding="utf-8"))

    assert saved_report == report
