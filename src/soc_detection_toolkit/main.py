from soc_detection_toolkit.ioc_parser import parse_iocs
from soc_detection_toolkit.json_reporter import save_json_report


def main() -> None:
    input_file = "data/sample_iocs.txt"
    output_file = "reports/ioc_report.json"

    results = parse_iocs(input_file)
    save_json_report(results, output_file)

    print("SOC Detection Toolkit - IOC Parser")
    print("----------------------------------")
    print(f"Detected IPs: {len(results['ips'])}")
    print(f"Detected URLs: {len(results['urls'])}")
    print(f"Detected Domains: {len(results['domains'])}")
    print(f"Detected Hashes: {len(results['hashes'])}")
    print(f"Detected Emails: {len(results['emails'])}")
    print(f"Unknown values: {len(results['unknown'])}")
    print(f"\nJSON report saved to: {output_file}")


if __name__ == "__main__":
    main()
