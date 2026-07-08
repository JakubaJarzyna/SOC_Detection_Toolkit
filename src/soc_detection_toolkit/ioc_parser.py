import re
from pathlib import Path


IP_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
URL_PATTERN = re.compile(r"^https?://[^\s]+$")
EMAIL_PATTERN = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_PATTERN = re.compile(r"^(?!https?://)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def parse_iocs(file_path: str) -> dict:
    results = {
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

        if IP_PATTERN.fullmatch(value):
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