import ipaddress
import re
from pathlib import Path

from soc_detection_toolkit.models import IOCResults

URL_PATTERN = re.compile(r"^https?://[^\s]+$")
EMAIL_PATTERN = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_PATTERN = re.compile(r"^(?!https?://)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def is_valid_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    return address.version == 4


def parse_iocs(file_path: str) -> IOCResults:
    results: IOCResults = {
        "ips": [],
        "urls": [],
        "domains": [],
        "hashes": [],
        "emails": [],
        "unknown": [],
    }

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    for line in path.read_text().splitlines():
        value = line.strip()

        if not value:
            continue

        if is_valid_ipv4(value):
            results["ips"].append(value)
        elif URL_PATTERN.fullmatch(value):
            results["urls"].append(value)
        elif EMAIL_PATTERN.fullmatch(value):
            results["emails"].append(value)
        elif HASH_PATTERN.fullmatch(value):
            results["hashes"].append(value)
        elif DOMAIN_PATTERN.fullmatch(value):
            results["domains"].append(value)
        else:
            results["unknown"].append(value)

    return results
