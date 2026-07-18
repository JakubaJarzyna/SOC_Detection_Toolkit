from pathlib import Path

import pytest

from soc_detection_toolkit.main import main


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
