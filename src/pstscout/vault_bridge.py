"""M2.2 prototype: search/inspect a .pstsc through the existing M1 Node reader.

Does NOT materialize a plaintext PST. The M1 inspect/attachment scripts are
started with an experimental byte-source hook; all content is sent in pipes.
Run only with synthetic or authorized test PSTs. NOT production audited.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterator


class BridgeError(Exception):
    """A sanitized failure in the encrypted PST bridge."""


def _paths() -> tuple[str, Path, Path, Path]:
    node = shutil.which('node')
    if not node:
        raise BridgeError('Node.js was not found (developer dependency)')
    folder = Path(__file__).parent / 'node'
    hook = folder / 'vault_hook.cjs'
    inspect = folder / 'inspect.mjs'
    attachment = folder / 'attachment.mjs'
    if not all(p.is_file() for p in (hook, inspect, attachment)):
        raise BridgeError('M1 and M2.2 helper files are not installed')
    if not (folder / 'node_modules' / 'pst-extractor' / 'package.json').is_file():
        raise BridgeError('PST parser is missing; run npm ci in src/pstscout/node')
    return node, hook, inspect, attachment


def _process(archive: Path, password: str, script: Path, *args: str) -> subprocess.Popen:
    node, hook, _, _ = _paths()
    if archive.suffix.lower() != '.pstsc' or not archive.is_file():
        raise BridgeError('Encrypted .pstsc archive not found')
    if not isinstance(password, str) or not password or '\n' in password or '\r' in password:
        raise BridgeError('Invalid password input')
    encoded = password.encode('utf-8')
    if len(encoded) > 1024:
        raise BridgeError('Password is too long')
    command = [node, '--require', str(hook), str(script), str(archive.resolve()), *args]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, bufsize=0)
    try:
        assert proc.stdin is not None
        proc.stdin.write(encoded + b'\n')
        proc.stdin.close()
        proc.stdin = None  # allow subprocess.communicate() after securely closing stdin
    except Exception:
        proc.kill()
        proc.wait()
        raise BridgeError('Unable to start encrypted archive reader') from None
    return proc


def iter_messages(archive: Path, password: str, *, limit: int = 5,
                  show_body: bool = False, body_cap: int = 65536) -> Iterator[dict]:
    if limit < 0 or body_cap < 1 or body_cap > 1024 * 1024:
        raise BridgeError('Invalid scan options')
    _, _, script, _ = _paths()
    proc = _process(archive, password, script, str(limit), '1' if show_body else '0', str(body_cap))
    has_summary = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            try:
                item = json.loads(line)
                if not isinstance(item, dict) or item.get('type') not in {'summary', 'message'}:
                    raise ValueError('unexpected event')
            except (ValueError, UnicodeError):
                raise BridgeError('Encrypted PST reader returned invalid events') from None
            if item['type'] == 'summary':
                has_summary = True
            yield item
        code = proc.wait()
        if code != 0 or not has_summary:
            raise BridgeError(f'Encrypted PST reader failed or was incomplete (exit={code})')
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stdout:
            proc.stdout.close()


def probe_attachment(archive: Path, password: str, message_id: str, index: int,
                     max_mib: int = 64) -> tuple[int, str]:
    if not message_id.isdecimal() or len(message_id) > 24 or index < 0 or not 1 <= max_mib <= 1024:
        raise BridgeError('Invalid attachment request')
    _, _, _, script = _paths()
    proc = _process(archive, password, script, message_id, str(index))
    digest = hashlib.sha256()
    count = 0
    try:
        assert proc.stdout is not None
        while chunk := proc.stdout.read(1024 * 1024):
            count += len(chunk)
            if count > max_mib * 1024 * 1024:
                raise BridgeError('Attachment exceeds configured size limit')
            digest.update(chunk)
        code = proc.wait()
        if code != 0:
            raise BridgeError(f'Encrypted PST attachment reader failed (exit={code})')
        return count, digest.hexdigest()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stdout:
            proc.stdout.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog='python -m pstscout.vault_bridge',
                                description='M2.2 encrypted PST read-only proof of concept')
    sub = p.add_subparsers(dest='action', required=True)
    inspect = sub.add_parser('inspect')
    inspect.add_argument('--archive', type=Path, required=True)
    inspect.add_argument('--limit', type=int, default=5)
    inspect.add_argument('--count-only', action='store_true')
    inspect.add_argument('--show-body', action='store_true')
    inspect.add_argument('--body-cap', type=int, default=65536)
    att = sub.add_parser('attachment-probe')
    att.add_argument('--archive', type=Path, required=True)
    att.add_argument('--message-id', required=True)
    att.add_argument('--index', type=int, required=True)
    att.add_argument('--max-mib', type=int, default=64)
    args = p.parse_args(argv)
    try:
        password = getpass.getpass('Archive password (not stored): ')
        if args.action == 'inspect':
            for row in iter_messages(args.archive, password, limit=args.limit,
                                     show_body=args.show_body, body_cap=args.body_cap):
                if row['type'] == 'summary':
                    print('SUMMARY messages={messages} folders={folders} skipped={skipped} limited={limited}'.format(**row))
                    if row.get('skipped'):
                        reasons = row.get('skipped_by_reason') or {}
                        if reasons:
                            print('SKIP_REASONS ' + ' '.join(f'{key}={value}' for key, value in reasons.items()))
                        hints = row.get('folder_error_hints') or {}
                        if hints:
                            print('FOLDER_ERROR_HINTS ' + ' '.join(f'{key}={value}' for key, value in hints.items()))
                elif not args.count_only:
                    print(f"ID: {row.get('identifier', '')} | {row.get('delivery_time') or row.get('submit_time') or '-'}")
                    print(f"Folder: {row.get('folder_path', '')} | Subject: {row.get('subject', '')}")
                    print(f"From: {row.get('sender_name', '')} <{row.get('sender_email', '')}>")
                    print('Attachments:', [(a.get('index'), a.get('name')) for a in row.get('attachments', [])])
                    if args.show_body:
                        print('Body:', row.get('body', ''))
                    print('---')
        else:
            length, digest = probe_attachment(args.archive, password, args.message_id, args.index,
                                              max_mib=args.max_mib)
            print(f'Attachment read successfully: {length} bytes; SHA256={digest}')
        return 0
    except (BridgeError, FileNotFoundError, PermissionError) as exc:
        # Do not expose raw Node exception, vault contents, keys or user paths.
        detail = str(exc) if isinstance(exc, BridgeError) else 'Encrypted archive inaccessible'
        print(f'M2.2 ERROR: {detail}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
