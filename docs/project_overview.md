# Project Overview

SOC Detection Toolkit is a Python-based cybersecurity project designed to simulate selected tasks performed by a SOC analyst.

## Module 1: IOC Parser

The first module focuses on parsing Indicators of Compromise (IOCs) from a text file.

The parser will identify and categorize:

- IP addresses
- Domains
- URLs
- File hashes
- Email addresses

## Why this module matters

IOC parsing is a common task in security operations. Analysts often work with suspicious IP addresses, domains, URLs, hashes, and email addresses during phishing investigations, malware analysis, and incident response.

## Planned workflow

1. Read indicators from a sample text file.
2. Use regular expressions to detect IOC types.
3. Categorize indicators into structured groups.
4. Export results to JSON or Markdown report in later stages.

## Technologies used

- Python
- Regular expressions
- Markdown