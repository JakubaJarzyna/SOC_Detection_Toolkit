import argparse
import sys
from collections.abc import Sequence

from soc_detection_toolkit.ioc_parser import parse_iocs
from soc_detection_toolkit.json_reporter import save_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-detection-toolkit",
        description="Parse indicators of compromise and generate a JSON report.",
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the input file containing IOC values.",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path where the JSON report will be saved.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        results = parse_iocs(args.input)
        save_json_report(results, args.output)
    except OSError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print("SOC Detection Toolkit - IOC Parser")
    print("----------------------------------")
    print(f"Detected IPs: {len(results['ips'])}")
    print(f"Detected URLs: {len(results['urls'])}")
    print(f"Detected Domains: {len(results['domains'])}")
    print(f"Detected Hashes: {len(results['hashes'])}")
    print(f"Detected Emails: {len(results['emails'])}")
    print(f"Unknown values: {len(results['unknown'])}")
    print(f"\nJSON report saved to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
