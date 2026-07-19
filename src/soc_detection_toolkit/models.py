from typing import TypedDict


class IOCResults(TypedDict):
    ips: list[str]
    urls: list[str]
    domains: list[str]
    hashes: list[str]
    emails: list[str]
    unknown: list[str]


class IOCCounts(TypedDict):
    ips: int
    urls: int
    domains: int
    hashes: int
    emails: int
    unknown: int


class ReportMetadata(TypedDict):
    generated_at: str
    source_file: str
    total_items: int
    counts: IOCCounts


class IOCReport(TypedDict):
    metadata: ReportMetadata
    indicators: IOCResults
