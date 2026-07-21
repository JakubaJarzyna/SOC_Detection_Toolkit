from pathlib import Path

import pytest

from soc_detection_toolkit.main import main


def test_cli_generates_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_file = tmp_path / "iocs.txt"
    output_file = tmp_path / "report.json"

    input_file.write_text(
        "\n".join(
            [
                "192.168.1.10",
                "example.com",
                "analyst@example.com",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert output_file.exists()
    assert "Detected IPs: 1" in captured.out
    assert "Detected Domains: 1" in captured.out
    assert "Detected Emails: 1" in captured.out
    assert f"JSON report saved to: {output_file}" in captured.out
    assert captured.err == ""


def test_cli_returns_error_for_missing_input_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_input = tmp_path / "missing.txt"
    output_file = tmp_path / "report.json"

    exit_code = main(
        [
            "--input",
            str(missing_input),
            "--output",
            str(output_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error:" in captured.err
    assert "File not found:" in captured.err
    assert not output_file.exists()


def test_cli_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    captured = capsys.readouterr()

    assert "--deduplicate" in captured.out
    assert error.value.code == 0
    assert "usage: soc-detection-toolkit" in captured.out
    assert "--input" in captured.out
    assert "--output" in captured.out
    assert captured.err == ""


def test_cli_requires_input_and_output_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main([])

    captured = capsys.readouterr()

    assert error.value.code == 2
    assert "the following arguments are required" in captured.err
    assert "--input" in captured.err
    assert "--output" in captured.err


def test_cli_warns_when_input_file_is_empty(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_file = tmp_path / "empty.txt"
    output_file = tmp_path / "report.json"

    input_file.write_text("", encoding="utf-8")

    exit_code = main(
        [
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert output_file.exists()
    assert "Warning: no indicators were found" in captured.err


def test_cli_deduplicates_indicators_when_flag_is_used(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    input_file = tmp_path / "iocs.txt"
    output_file = tmp_path / "report.json"

    input_file.write_text(
        "\n".join(
            [
                "192.168.1.10",
                "192.168.1.10",
                "example.com",
                "example.com",
            ]
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--input",
            str(input_file),
            "--output",
            str(output_file),
            "--deduplicate",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Detected IPs: 1" in captured.out
    assert "Detected Domains: 1" in captured.out
    assert captured.err == ""
