import argparse
import sys
from collections.abc import Sequence

from soc_detection_toolkit.csv_reporter import save_csv_report
from soc_detection_toolkit.ioc_parser import deduplicate_results, parse_iocs
from soc_detection_toolkit.json_reporter import build_report, save_json_report


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

    parser.add_argument(
        "--deduplicate",
        action="store_true",
        help="Remove duplicate IOC values while preserving their original order.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="Output report format. Default: json.",
)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        results = parse_iocs(args.input)

        if args.deduplicate:
            results = deduplicate_results(results)

        if not any(results.values()):
            print(
                "Warning: no indicators were found in the input file.",
                file=sys.stderr,
            )

        if args.format == "csv":
            save_csv_report(results, args.output)
        else:
            report = build_report(results, args.input)
            save_json_report(report, args.output)

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
    print(f"\n{args.format.upper()} report saved to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
