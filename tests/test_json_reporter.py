import json
from pathlib import Path

from soc_detection_toolkit.json_reporter import save_json_report
from soc_detection_toolkit.models import IOCResults


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

    save_json_report(results, str(output_file))

    assert output_file.exists()

    saved_results = json.loads(output_file.read_text(encoding="utf-8"))

    assert saved_results == results


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

    save_json_report(results, str(output_file))

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

    save_json_report(results, str(output_file))

    saved_results = json.loads(output_file.read_text(encoding="utf-8"))

    assert saved_results == results
