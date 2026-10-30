"""PSTScout M2.1 local development CLI (never prints or persists passwords)."""
from __future__ import annotations

import argparse
import getpass
import hashlib
from pathlib import Path

from .vault import EncryptedPST, VaultError, AuthenticationError, InvalidArchiveError, SourceChangedError, encrypt_file


# Vault errors can contain unexpected diagnostic text. Only explicitly
# allowlisted internal messages may be shown; raw exception strings, paths,
# passwords, keys and PST contents must never reach console/log output.
_SAFE_VAULT_ERRORS = {
    "Password must be 1–1024 UTF-8 bytes": "Password must be between 1 and 1024 UTF-8 bytes.",
    "Use a unique password at least 16 UTF-8 bytes long":
        "Password too short: choose at least 16 UTF-8 bytes (prefer a long passphrase).",
    "Source and destination must be different": "Source and destination must be different.",
    "Unsupported source size": "Unsupported source file size.",
    "Too many chunks": "Source file is too large for this archive format.",
}


def _print_safe_error(exc: Exception) -> None:
    if type(exc) is VaultError:
        detail = _SAFE_VAULT_ERRORS.get(str(exc))
        print(f"Vault error: {detail}" if detail else "Vault error: operation rejected")
    elif isinstance(exc, AuthenticationError):
        print("Vault error: invalid password or authentication failure")
    elif isinstance(exc, InvalidArchiveError):
        print("Vault error: invalid, damaged or unsupported archive")
    elif isinstance(exc, SourceChangedError):
        print("Vault error: source was modified while encrypting; retry with a stable source")
    elif isinstance(exc, FileExistsError):
        print("Vault error: output already exists; choose a different output name")
    elif isinstance(exc, FileNotFoundError):
        print("Vault error: source or archive file was not found")
    elif isinstance(exc, PermissionError):
        print("Vault error: filesystem access denied")
    elif isinstance(exc, ValueError):
        print("Vault error: invalid input arguments")
    else:
        print(f"Vault error: {type(exc).__name__}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m pstscout.vault_cli")
    sub = p.add_subparsers(dest="action", required=True)
    enc = sub.add_parser("encrypt", help="create a new encrypted archive without modifying source")
    enc.add_argument("--source", type=Path, required=True)
    enc.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify", help="authenticate every encrypted chunk")
    verify.add_argument("--archive", type=Path, required=True)
    probe = sub.add_parser("probe", help="hash one random-access plaintext segment in memory")
    probe.add_argument("--archive", type=Path, required=True)
    probe.add_argument("--offset", type=int, required=True)
    probe.add_argument("--length", type=int, default=512)
    a = p.parse_args(argv)
    try:
        pw = getpass.getpass("Archive password (not stored): ")
        if a.action == "encrypt":
            again = getpass.getpass("Repeat password: ")
            if pw != again:
                print("Password confirmation failed")
                return 2
            n = encrypt_file(a.source, a.output, pw)
            print(f"Encrypted archive created: {n} authenticated chunks")
            print("ORIGINAL FILE UNCHANGED. Check integrity before considering any migration.")
            return 0
        with EncryptedPST(a.archive, pw) as archive:
            if a.action == "verify":
                n = archive.verify()
                print(f"Full archive verification OK: {n} authenticated chunks")
                return 0
            segment = archive.read_at(a.offset, a.length)
            print(f"Random-access probe: {len(segment)} bytes; SHA256={hashlib.sha256(segment).hexdigest()}")
            return 0
    except (VaultError, FileExistsError, FileNotFoundError, ValueError, OSError) as exc:
        _print_safe_error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
