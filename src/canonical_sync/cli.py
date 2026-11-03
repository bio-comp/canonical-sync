"""Operator command-line surface for canonical-sync."""

from __future__ import annotations

import argparse
import sys

from . import adc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="canonical-sync")
    parser.add_argument("command", nargs="?", choices=("refresh-google-drive-adc",))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "refresh-google-drive-adc":
        return adc.main(args[1:])
    parser = _parser()
    parsed = parser.parse_args(args)
    if parsed.command is None:
        parser.print_help()
        return 0
    raise AssertionError("unreachable command dispatch")


if __name__ == "__main__":
    raise SystemExit(main())
