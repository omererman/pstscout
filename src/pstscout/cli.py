"""M0-only diagnostic entry point. Not the PST search application."""

from __future__ import annotations

import argparse
from pathlib import Path

from .portable import check_volume_access


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pstscout")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="check portable USB read/write access")
    doctor.add_argument("--root", type=Path, required=True, help="USB root to inspect")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        result = check_volume_access(args.root)
        print("PSTScout M0 diagnostics (no PST files accessed)")
        print(f"USB readable: {'YES' if result.readable else 'NO'}")
        print(f"USB writable: {'YES' if result.writable else 'NO'}")
        print("ENCRYPTED VAULT: NOT IMPLEMENTED; DO NOT IMPORT REAL ARCHIVES")
        return 0 if result.readable and result.writable else 1
    return 2
