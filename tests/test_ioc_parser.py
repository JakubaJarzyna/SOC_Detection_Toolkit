from pathlib import Path

import pytest

from soc_detection_toolkit.ioc_parser import parse_iocs


def write_ioc_file(tmp_path: Path, content: str) -> Path:
    input_file = tmp_path / "iocs.txt"
    input_file.write_text(content, encoding="utf-8")
    return input_file


def test_parse_ipv4(tmp_path: Path) -> None:
    input_file = write_ioc_file(tmp_path, "192.168.1.10\n")

    result = parse_iocs(str(input_file))

    assert result["ips"] == ["192.168.1.10"]
    assert result["unknown"] == []


def test_parse_url(tmp_path: Path) -> None:
    input_file = write_ioc_file(tmp_path, "https://example.com/path\n")

    result = parse_iocs(str(input_file))

    assert result["urls"] == ["https://example.com/path"]


def test_parse_domain(tmp_path: Path) -> None:
    input_file = write_ioc_file(tmp_path, "example.com\n")

    result = parse_iocs(str(input_file))

    assert result["domains"] == ["example.com"]


def test_parse_email(tmp_path: Path) -> None:
    input_file = write_ioc_file(tmp_path, "analyst@example.com\n")

    result = parse_iocs(str(input_file))

    assert result["emails"] == ["analyst@example.com"]


@pytest.mark.parametrize(
    "hash_value",
    [
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ],
)
def test_parse_supported_hashes(tmp_path: Path, hash_value: str) -> None:
    input_file = write_ioc_file(tmp_path, f"{hash_value}\n")

    result = parse_iocs(str(input_file))

    assert result["hashes"] == [hash_value]


def test_parse_unknown_value(tmp_path: Path) -> None:
    input_file = write_ioc_file(tmp_path, "not-an-ioc\n")

    result = parse_iocs(str(input_file))

    assert result["unknown"] == ["not-an-ioc"]


def test_skip_empty_lines_and_strip_whitespace(tmp_path: Path) -> None:
    input_file = write_ioc_file(
        tmp_path,
        "\n   \n  192.168.1.10  \n",
    )

    result = parse_iocs(str(input_file))

    assert result["ips"] == ["192.168.1.10"]
    assert result["unknown"] == []


def test_parse_multiple_ioc_types(tmp_path: Path) -> None:
    input_file = write_ioc_file(
        tmp_path,
        "\n".join(
            [
                "192.168.1.10",
                "https://example.com/login",
                "example.org",
                "soc@example.org",
                "d41d8cd98f00b204e9800998ecf8427e",
                "unrecognized-value",
            ]
        ),
    )

    result = parse_iocs(str(input_file))

    assert result == {
        "ips": ["192.168.1.10"],
        "urls": ["https://example.com/login"],
        "domains": ["example.org"],
        "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        "emails": ["soc@example.org"],
        "unknown": ["unrecognized-value"],
    }


def test_preserve_duplicate_values(tmp_path: Path) -> None:
    input_file = write_ioc_file(
        tmp_path,
        "example.com\nexample.com\n",
    )

    result = parse_iocs(str(input_file))

    assert result["domains"] == ["example.com", "example.com"]


def test_raise_file_not_found_error() -> None:
    missing_file = "file-that-does-not-exist.txt"

    with pytest.raises(
        FileNotFoundError,
        match="File not found: file-that-does-not-exist.txt",
    ):
        parse_iocs(missing_file)


def test_invalid_ipv4_is_unknown(tmp_path: Path) -> None:
    input_file = write_ioc_file(tmp_path, "999.999.999.999\n")

    result = parse_iocs(str(input_file))

    assert result["ips"] == []
    assert result["unknown"] == ["999.999.999.999"]
