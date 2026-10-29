"""PSTScout developer commands; M1 reads sources but does not archive/index."""
from __future__ import annotations

import argparse
from pathlib import Path

from .portable import check_volume_access
from .reader import PSTReader, PSTReaderError, ScanSummary, MessageInfo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pstscout")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor", help="check USB read/write access")
    doctor.add_argument("--root", type=Path, required=True)
    sub.add_parser("pst-doctor", help="check Node and PST helper installation (without opening PSTs)")

    inspect = sub.add_parser("inspect", help="read PST directly; does not create an index")
    inspect.add_argument("--pst", required=True, type=Path)
    inspect.add_argument("--limit", type=int, default=20, help="max messages, 0 = scan all")
    inspect.add_argument("--show-body", action="store_true", help="display private message body")
    inspect.add_argument("--count-only", action="store_true", help="only show scan totals; limit=0 scans entire PST")
    inspect.add_argument("--body-cap", type=int, default=65536, help="maximum characters per message")

    att = sub.add_parser("attachment-probe", help="verify attachment streaming without saving content")
    att.add_argument("--pst", required=True, type=Path)
    att.add_argument("--message-id", required=True)
    att.add_argument("--index", required=True, type=int)
    att.add_argument("--max-mib", type=int, default=64)

    args = parser.parse_args(argv)
    if args.command == "doctor":
        status = check_volume_access(args.root)
        print("PSTScout USB diagnostics (no mail files accessed)")
        print(f"USB readable: {'YES' if status.readable else 'NO'}")
        print(f"USB writable: {'YES' if status.writable else 'NO'}")
        print("ENCRYPTION: NOT IMPLEMENTED; DO NOT IMPORT SENSITIVE ARCHIVES")
        return 0 if status.readable and status.writable else 1

    reader = PSTReader()
    if args.command == "pst-doctor":
        ok, info = reader.doctor()
        print(info)
        return 0 if ok else 1
    try:
        if args.command == "inspect":
            for event in reader.events(args.pst, limit=args.limit,
                                       include_body=args.show_body, body_cap=args.body_cap):
                if isinstance(event, ScanSummary):
                    print(f"SUMMARY messages={event.messages} folders={event.folders} "
                          f"skipped={event.skipped} limited={event.limited}")
                    if event.skipped:
                        print("SKIP_REASONS " + " ".join(
                            f"{name}={value}" for name, value in event.skipped_by_reason.items()
                        ))
                        if event.skipped_by_reason.get("folder_read_error", 0):
                            print("FOLDER_ERROR_HINTS " + " ".join(
                                f"{key}={value}" for key, value in event.folder_error_hints.items()
                            ))
                            print("WARNING: folder traversal failed; metadata hints alone do not prove completeness")
                elif isinstance(event, MessageInfo):
                    if args.count_only:
                        continue
                    # CLI intentionally does not create machine-readable logs.
                    print(f"ID: {event.identifier} | {event.delivery_time or event.submit_time or '-'}")
                    print(f"Folder: {event.folder_path} | Subject: {event.subject}")
                    print(f"From: {event.sender_name} <{event.sender_email}>")
                    print(f"Recipients: {', '.join(event.recipients)}")
                    print(f"Attachments: {[(a.index, a.name, a.size) for a in event.attachments]}")
                    if args.show_body:
                        print(f"Body: {event.body}")
                        if event.body_truncated:
                            print("[body truncated]")
                    print("---")
            return 0
        if args.command == "attachment-probe":
            probe = reader.attachment_probe(args.pst, args.message_id, args.index,
                                            max_bytes=args.max_mib * 1024 * 1024)
            print(f"Attachment read successfully: {probe.bytes_read} bytes")
            print(f"SHA256 (test only): {probe.sha256}")
            return 0
    except (PSTReaderError, ValueError, FileNotFoundError) as exc:
        # Sanitized errors only; never print library stderr, secrets or mail bodies.
        print(f"M1 ERROR: {type(exc).__name__}: {exc if isinstance(exc, PSTReaderError) else 'invalid input'}")
        return 1
    return 2
