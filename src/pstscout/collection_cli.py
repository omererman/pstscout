"""M3.3 collection CLI: migrate old index once; add, discover and search PSTs.

No passwords in argv or logs. The index itself remains SQLCipher-encrypted.
"""
from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from .collection import (
    CollectionError, _read_registry, _source_info, add_archive,
    collection_info, migrate_legacy, scan_root,
)
from .secure_index import SecureIndexError, SecureSearchIndex
from .search_index import IndexErrorM3
from .vault_bridge import BridgeError
from .vault import EncryptedPST, VaultError


def _input_password(label: str) -> str:
    return getpass.getpass(label)


def _scan_new(index_path: Path, root: Path, password: str) -> tuple[list[Path], int]:
    """Find only new archive identities, without opening mail content."""
    if not root.is_dir():
        raise CollectionError('Archive root directory does not exist')
    with SecureSearchIndex(index_path, password) as db:
        records = _read_registry(db)
    known_ids = {x.fingerprint for x in records}
    known_paths = {x.relative_path.casefold() for x in records}
    new: list[Path] = []
    seen = set()
    conflicted = 0
    for path in sorted(root.rglob('*.pstsc')):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            source_id, rel, _, _ = _source_info(root, path)
        except (CollectionError, OSError):
            conflicted += 1
            continue
        if source_id in known_ids or source_id in seen:
            continue
        if rel.casefold() in known_paths:
            conflicted += 1
            continue
        new.append(path)
        seen.add(source_id)
    return new, conflicted


def _print_status(index_path: Path, password: str) -> None:
    count, rows = collection_info(index_path, password)
    print(f'M3.3 COLLECTION: archives={len(rows)} messages={count}')
    print(f'INDEX_HEALTH: skipped={sum(x.skipped for x in rows)} '
          f'body_truncated={sum(x.body_truncated for x in rows)} '
          f'limited_archives={sum(x.limited for x in rows)}')
    print('READY: Searches use the encrypted index, not the PST files.')


def _search(index_path: Path, password: str, show_results: bool) -> int:
    with SecureSearchIndex(index_path, password) as db:
        records = _read_registry(db)
        total = db.count()
        if total != sum(x.indexed for x in records):
            raise CollectionError('Archive registry and index totals differ')
        print(f'M3.3 SEARCH READY: archives={len(records)} messages={total}')
        print('PST files will not be rescanned.')
        while True:
            try:
                text = input('Search text (empty to quit): ').strip()
            except (EOFError, KeyboardInterrupt):
                print('\nSearch ended')
                break
            if not text:
                break
            try:
                rows = db.search(text)
                print(f'MATCHES_SHOWN: {len(rows)} (up to 20, not total match count)')
                if show_results:
                    for row in rows:
                        print(f'Archive={row.archive_id[:12]} ID={row.message_id} '
                              f'Subject={row.subject} From={row.sender_email} Date={row.sent_at}')
            except (ValueError, IndexErrorM3, SecureIndexError):
                print('SEARCH ERROR: invalid phrase or unavailable encrypted query')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m pstscout.collection_cli',
                                    description='M3.3 encrypted multi-archive index preview')
    subs = parser.add_subparsers(dest='command', required=True)

    m = subs.add_parser('migrate', help='Copy M3.2 index into a new M3.3 collection')
    m.add_argument('--legacy-index', type=Path, required=True)
    m.add_argument('--index', type=Path, required=True)
    m.add_argument('--archive', type=Path, required=True,
                   help='the original .pstsc corresponding to the M3.2 index')
    m.add_argument('--root', type=Path, required=True)

    a = subs.add_parser('add', help='Index only a new .pstsc archive')
    a.add_argument('--index', type=Path, required=True)
    a.add_argument('--archive', type=Path, required=True)
    a.add_argument('--root', type=Path, required=True)
    a.add_argument('--max-messages', type=int, default=0,
                   help='M3.3 accepts 0 only; all messages must be scanned')
    a.add_argument('--body-cap', type=int, default=65536)
    a.add_argument('--verify-source', action='store_true',
                   help='verify all encrypted source chunks before indexing')

    sync = subs.add_parser('sync', help='Detect and index ONLY new .pstsc files in root')
    sync.add_argument('--index', type=Path, required=True)
    sync.add_argument('--root', type=Path, required=True)
    sync.add_argument('--max-messages', type=int, default=0)
    sync.add_argument('--body-cap', type=int, default=65536)
    sync.add_argument('--verify-source', action='store_true',
                      help='authenticate every chunk of each new encrypted source first')

    scan = subs.add_parser('scan', help='Detect new, missing, moved and changed archives')
    scan.add_argument('--index', type=Path, required=True)
    scan.add_argument('--root', type=Path, required=True)

    status = subs.add_parser('status', help='Show encrypted registry statistics')
    status.add_argument('--index', type=Path, required=True)

    verify = subs.add_parser('verify', help='Check SQLCipher and registry integrity')
    verify.add_argument('--index', type=Path, required=True)

    search = subs.add_parser('search', help='Query across all registered PST archives')
    search.add_argument('--index', type=Path, required=True)
    search.add_argument('--show-results', action='store_true',
                        help='Print sensitive subject/sender information to the terminal')

    args = parser.parse_args(argv)
    if args.command in {'add', 'sync'} and (args.max_messages != 0 or not 1 <= args.body_cap <= 1048576):
        parser.error('Invalid message count or body cap')
    try:
        if args.command == 'migrate':
            pw = _input_password('Existing M3.2 index password: ')
            rec = migrate_legacy(args.legacy_index, args.index, args.archive, args.root, pw)
            print(f'M3.3 MIGRATION OK: archives=1 indexed_messages={rec.indexed}')
            print('Original M3.2 index left unchanged.')
            return 0
        if args.command == 'scan':
            pw = _input_password('Collection index password: ')
            result = scan_root(args.index, args.root, pw)
            print('SCAN registered={registered} present={present} new={new} '
                  'moved={moved} changed={changed} missing={missing} '
                  'duplicates={duplicates} unreadable={unreadable}'.format(**vars(result)))
            print('SCAN WARNING: fast file identity checks do not authenticate every encrypted chunk.')
            return 0
        if args.command == 'status':
            _print_status(args.index, _input_password('Collection index password: '))
            return 0
        if args.command == 'verify':
            pw = _input_password('Collection index password: ')
            with SecureSearchIndex(args.index, pw) as db:
                rows = _read_registry(db)
                count = db.check_integrity()
                if count != sum(x.indexed for x in rows):
                    raise CollectionError('Archive registry and index totals differ')
            print(f'M3.3 VERIFIED: archives={len(rows)} indexed_messages={count}')
            return 0
        if args.command == 'search':
            return _search(args.index, _input_password('Collection index password: '),
                           args.show_results)
        if args.command == 'add':
            pw = _input_password('Collection index password: ')
            # Check existing identity before prompting for new archive password.
            with SecureSearchIndex(args.index, pw) as db:
                old = _read_registry(db)
                ident, rel, _, _ = _source_info(args.root, args.archive)
                if any(r.fingerprint == ident for r in old):
                    # The add operation also reconciles a renamed path.
                    result, rec = add_archive(args.index, args.root, args.archive, pw, pw)
                    print(f'M3.3 ARCHIVE {result.upper()}: no message reindex performed')
                    return 0
            archive_pw = _input_password('New encrypted PST password: ')
            if args.verify_source:
                with EncryptedPST(args.archive, archive_pw) as source:
                    source.verify()
                print('SOURCE VERIFIED: all encrypted chunks authenticated')
            result, rec = add_archive(args.index, args.root, args.archive, pw,
                                      archive_pw, max_messages=args.max_messages,
                                      body_cap=args.body_cap)
            print(f'M3.3 ARCHIVE {result.upper()}: indexed_messages={rec.indexed if rec else 0}')
            if rec and (rec.skipped or rec.body_truncated or rec.limited):
                print(f'WARNING: skipped={rec.skipped}, body_truncated={rec.body_truncated}, '
                      f'limited={rec.limited}')
            return 0
        if args.command == 'sync':
            pw = _input_password('Collection index password: ')
            new, conflicts = _scan_new(args.index, args.root, pw)
            print(f'M3.3 DISCOVERY: new_archives={len(new)} conflicts={conflicts}')
            if conflicts:
                print('WARNING: Some archive locations are unreadable or changed; none are overwritten.')
            for number, archive in enumerate(new, 1):
                print(f'Indexing new archive {number} of {len(new)}')
                archive_pw = _input_password('Encrypted PST password: ')
                if args.verify_source:
                    with EncryptedPST(archive, archive_pw) as source:
                        source.verify()
                    print(f'ARCHIVE {number}: encrypted chunks verified')
                result, rec = add_archive(args.index, args.root, archive, pw, archive_pw,
                                          max_messages=args.max_messages,
                                          body_cap=args.body_cap)
                print(f'ARCHIVE {number}: {result.upper()} '
                      f'indexed_messages={rec.indexed if rec else 0}')
            _print_status(args.index, pw)
            return 0
    except (CollectionError, SecureIndexError, BridgeError, VaultError,
            FileNotFoundError, OSError, KeyboardInterrupt, IndexErrorM3) as exc:
        # Never print raw third-party parser errors, file paths, exception
        # tracebacks or any plaintext mail data.
        if isinstance(exc, CollectionError):
            allowed = {
                'Archive must be inside the selected root directory',
                'Invalid archive location', 'Source must be a .pstsc encrypted archive',
                'Cannot read the encrypted source header',
                'Original M3.2 index is missing',
                'Choose a new, nonexisting M3.3 index filename',
                'Archive root directory does not exist',
                'Original PST does not match the existing M3.2 index',
                'M3.2 index message counts do not agree',
                'Legacy M3.2 index is partial; use the full index',
                'Insufficient free space to clone encrypted index',
                'Unable to migrate encrypted M3.2 index',
                'Existing archive path has changed contents; replacement requires M3.4',
                'Encrypted index could not be opened or updated',
                'Index is not a supported M3.3 collection',
                'Source archive changed during indexing',
                'Archive registry and index totals differ',
            }
            detail = str(exc) if str(exc) in allowed else 'Collection operation failed'
            print('M3.3 ERROR: ' + detail)
        else:
            print('M3.3 ERROR: encrypted index or source operation failed')
        return 1
    except Exception:
        # Last-resort privacy boundary. Never expose raw parser/SQLite errors.
        print('M3.3 ERROR [UNEXPECTED]: operation stopped; sensitive details hidden')
        return 1
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
