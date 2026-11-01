"""M3.2 encrypted persistent FTS index command-line prototype.

Build: the index database and any staging/journals are SQLCipher-encrypted.
Search: opens the completed encrypted DB without reading the PST again.
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
from pathlib import Path

from .search_index import IndexErrorM3
from .secure_index import SecureIndexError, SecureSearchIndex, source_fingerprint
from .vault_bridge import BridgeError, iter_messages


def _safe_remove(path: Path) -> None:
    """Best-effort cleanup of temporary ENCRYPTED database and journals."""
    for candidate in (path, Path(str(path) + '-journal'),
                      Path(str(path) + '-wal'), Path(str(path) + '-shm')):
        try:
            candidate.unlink(missing_ok=True)
        except OSError:
            pass


def build(archive: Path, output: Path, *, limit: int, body_cap: int) -> int:
    if not archive.is_file() or archive.suffix.lower() != '.pstsc':
        raise SecureIndexError('Encrypted PST archive was not found')
    if output.exists():
        raise SecureIndexError('Index output already exists; choose another filename')
    if not output.parent.is_dir():
        raise SecureIndexError('Index output directory does not exist')
    if not output.name or output.name.startswith('.'):
        raise SecureIndexError('Choose a visible index filename')

    password = getpass.getpass('Archive/index password (not stored): ')
    source_id = source_fingerprint(archive)
    stage = output.with_name(output.name + '.building-' + secrets.token_hex(8))
    published = False
    try:
        with SecureSearchIndex(stage, password, create=True) as index:
            events = iter_messages(archive, password, limit=limit,
                                   show_body=True, body_cap=body_cap)
            summary = index.build(events, archive_id=source_id)
            index.finalize(summary, source_id)
        # Reopen and confirm the encrypted database before publicizing it.
        with SecureSearchIndex(stage, password) as verify:
            if verify.info()['indexed'] != summary.indexed:
                raise SecureIndexError('Persisted index counts changed')
            verify.check_integrity()
        if output.exists():
            raise SecureIndexError('Index output was created concurrently')
        # Same-folder rename is atomic on NTFS. On Windows it does not replace
        # an existing file. Do not run concurrent builds to the same filename.
        os.rename(stage, output)
        published = True
        print(f'M3 ENCRYPTED INDEX: messages={summary.indexed} '
              f'folders={summary.folders_reported} skipped={summary.skipped_reported} '
              f'limited={summary.limited} body_truncated={summary.body_truncated}')
        print('INDEX SAVED: SQLCipher encrypted database')
        if summary.skipped_reported or summary.body_truncated:
            print('WARNING: Some source items or body text are not completely indexed.')
        return 0
    finally:
        if not published:
            _safe_remove(stage)


def search(index_path: Path, *, show_results: bool) -> int:
    password = getpass.getpass('Index password (not stored): ')
    with SecureSearchIndex(index_path, password) as index:
        meta = index.info()
        print(f'M3 ENCRYPTED INDEX OPEN: messages={meta["indexed"]} '
              f'folders={meta["folders"]} skipped={meta["skipped"]} '
              f'limited={bool(meta["limited"])} body_truncated={meta["body_truncated"]}')
        print('READY: Search works without rescanning the PST.')
        if meta['skipped'] or meta['body_truncated']:
            print('WARNING: Some source items or body text may be unavailable in search.')
        while True:
            try:
                phrase = input('Search text (empty to quit): ').strip()
            except (EOFError, KeyboardInterrupt):
                print('\nSearch session ended')
                break
            if not phrase:
                break
            try:
                results = index.search(phrase)
                print(f'MATCHES_SHOWN: {len(results)} (maximum 20; full match count not calculated)')
                if show_results:
                    for hit in results:
                        print(f'ID={hit.message_id} | {hit.sent_at} | {hit.subject} | '
                              f'{hit.sender_email} | {hit.folder}')
            except (ValueError, IndexErrorM3, SecureIndexError):
                print('SEARCH ERROR: invalid phrase or encrypted query failure')
    return 0


def verify(index_path: Path) -> int:
    password = getpass.getpass('Index password (not stored): ')
    with SecureSearchIndex(index_path, password) as index:
        count = index.check_integrity()
        print(f'M3 ENCRYPTED INDEX VERIFIED: messages={count}')
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog='python -m pstscout.persistent_cli',
                                description='M3.2 persistent encrypted SQLCipher FTS5 preview')
    subs = p.add_subparsers(dest='action', required=True)
    creator = subs.add_parser('build', help='Create new encrypted index from a .pstsc archive')
    creator.add_argument('--archive', type=Path, required=True)
    creator.add_argument('--index', type=Path, required=True)
    creator.add_argument('--max-messages', type=int, default=200,
                         help='0 for full archive; 200 default safe preview')
    creator.add_argument('--body-cap', type=int, default=65536)
    reader = subs.add_parser('search', help='Search existing encrypted index, no PST scan')
    reader.add_argument('--index', type=Path, required=True)
    reader.add_argument('--show-results', action='store_true')
    checker = subs.add_parser('verify', help='Check encrypted index page and schema integrity')
    checker.add_argument('--index', type=Path, required=True)
    args = p.parse_args(argv)
    if args.action == 'build' and (args.max_messages < 0 or not 1 <= args.body_cap <= 1048576):
        p.error('Invalid message limit or body cap')
    try:
        if args.action == 'build':
            return build(args.archive, args.index, limit=args.max_messages,
                         body_cap=args.body_cap)
        if args.action == 'search':
            return search(args.index, show_results=args.show_results)
        return verify(args.index)
    except (BridgeError, SecureIndexError, IndexErrorM3) as exc:
        # Error messages from these classes are sanitized internally except
        # bridge messages containing an exit code. Never show unexpected data.
        if isinstance(exc, SecureIndexError):
            print('M3.2 ERROR: ' + str(exc))
        elif isinstance(exc, BridgeError):
            print('M3.2 ERROR [PST_READER]: unable to read encrypted source')
        else:
            print('M3.2 ERROR [INDEX]: unable to build or query index')
        return 1
    except (OSError, KeyboardInterrupt):
        print('M3.2 ERROR [IO_OR_INTERRUPT]: operation failed; private details hidden')
        return 1
    except Exception:
        print('M3.2 ERROR [UNEXPECTED]: operation failed; private details hidden')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
