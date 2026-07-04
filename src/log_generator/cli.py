"""
Command-line interface for generating scenario output.
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from log_generator.scenario_yaml import ScenarioYamlError, generate_from_yaml


def build_parser() -> argparse.ArgumentParser:
    """
    Build the command-line argument parser.

    Returns:
        argparse.ArgumentParser: Parser configured with supported subcommands.
    """
    parser = argparse.ArgumentParser(prog="log-generator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser(
        "generate",
        help="generate an output tree from a YAML scenario",
    )
    generate_parser.add_argument("--scenario", required=True, help="YAML scenario file to load")
    generate_parser.add_argument("--output", required=True, help="output directory to write")
    generate_parser.add_argument("--run-id", help="explicit run ID for the output manifest")
    generate_parser.add_argument(
        "--generated-at",
        help="timezone-aware ISO 8601 generation timestamp for reproducible output",
    )
    generate_parser.add_argument(
        "--strict",
        action="store_true",
        help="reserved for future warning behavior; validation errors are always strict",
    )
    generate_parser.set_defaults(handler=_run_generate)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    Run the log-generator command-line interface.

    Args:
        argv (Optional[Sequence[str]]): Command arguments without the executable name.

    Returns:
        int: Process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    return args.handler(args)


def _run_generate(args: argparse.Namespace) -> int:
    """
    Generate output for the `generate` subcommand.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.

    Returns:
        int: Process exit code.
    """
    try:
        generated_at = _parse_generated_at(args.generated_at)
        manifest_path = generate_from_yaml(
            Path(args.scenario),
            Path(args.output),
            run_id=args.run_id,
            generated_at=generated_at,
        )
    except (OSError, ScenarioYamlError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote manifest: {manifest_path}")

    return 0


def _parse_generated_at(value: Optional[str]) -> Optional[datetime]:
    """
    Parse the optional generated-at timestamp.

    Args:
        value (Optional[str]): Raw timestamp value from the command line.

    Returns:
        Optional[datetime]: UTC-normalized timestamp, or None when omitted.
    """
    if value is None:
        return None

    try:
        parsed_value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("--generated-at must be a timezone-aware ISO 8601 timestamp") from exc

    if parsed_value.tzinfo is None or parsed_value.utcoffset() is None:
        raise ValueError("--generated-at must be timezone-aware")

    return parsed_value.astimezone(timezone.utc)


if __name__ == "__main__":
    raise SystemExit(main())
