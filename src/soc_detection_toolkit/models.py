from typing import TypedDict


class IOCResults(TypedDict):
    ips: list[str]
    urls: list[str]
    domains: list[str]
    hashes: list[str]
    emails: list[str]
    unknown: list[str]
