from soc_detection_toolkit.ioc_parser import parse_iocs


def main() -> None:
    results = parse_iocs("data/sample_iocs.txt")

    print("SOC Detection Toolkit - IOC Parser")
    print("----------------------------------")
    print(f"Detected IPs: {len(results['ips'])}")
    print(f"Detected URLs: {len(results['urls'])}")
    print(f"Detected Domains: {len(results['domains'])}")
    print(f"Detected Hashes: {len(results['hashes'])}")
    print(f"Detected Emails: {len(results['emails'])}")
    print(f"Unknown values: {len(results['unknown'])}")


if __name__ == "__main__":
    main()