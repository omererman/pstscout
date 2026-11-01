"""PSTScout M3.3: multiple immutable encrypted PST archives in one SQLCipher index.

- Never migrates the M3.2 index in place.
- New PSTs are indexed transactionally into a *separate* migrated index.
- Registry paths are relative to a user-supplied root and live only in SQLCipher.
- No plaintext SQLCipher/SQLite file, passphrase in argv, or file-content log.

DEVELOPMENT PREVIEW: full-file identity and secure deployment audits remain open.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .secure_index import SecureIndexError, SecureSearchIndex, source_fingerprint
from .vault_bridge import iter_messages


COLLECTION_VERSION = 1
_COPY_BUFFER = 4 * 1024 * 1024


class CollectionError(Exception):
    """Safe non-content diagnostic for M3.3 operations."""


@dataclass(frozen=True)
class RegisteredArchive:
    fingerprint: str
    relative_path: str
    size: int
    indexed: int
    reported: int
    folders: int
    skipped: int
    body_truncated: int
    limited: bool


@dataclass(frozen=True)
class ScanStatus:
    registered: int
    present: int
    moved: int
    new: int
    changed: int
    missing: int
    duplicates: int
    unreadable: int


def _under_root(root: Path, source: Path) -> str:
    try:
        relative = source.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise CollectionError('Archive must be inside the selected root directory') from None
    if not relative.parts or relative.is_absolute() or '..' in relative.parts:
        raise CollectionError('Invalid archive location')
    return relative.as_posix()


def _source_info(root: Path, archive: Path) -> tuple[str, str, int, int]:
    if archive.suffix.lower() != '.pstsc':
        raise CollectionError('Source must be a .pstsc encrypted archive')
    rel = _under_root(root, archive)
    try:
        source_id = source_fingerprint(archive)
        stat = archive.stat()
    except (OSError, SecureIndexError):
        raise CollectionError('Cannot read the encrypted source header') from None
    return source_id, rel, stat.st_size, stat.st_mtime_ns


def _schema(index: SecureSearchIndex) -> None:
    index._db.executescript('''
        CREATE TABLE pstscout_collection_meta (
            id INTEGER PRIMARY KEY CHECK(id=1),
            version INTEGER NOT NULL
        );
        INSERT INTO pstscout_collection_meta(id, version) VALUES(1, 1);
        CREATE TABLE pstscout_archives (
            fingerprint TEXT PRIMARY KEY,
            relative_path TEXT NOT NULL COLLATE NOCASE UNIQUE,
            bytes INTEGER NOT NULL CHECK(bytes >= 0),
            source_mtime_ns INTEGER NOT NULL,
            indexed INTEGER NOT NULL CHECK(indexed >= 0),
            reported INTEGER NOT NULL CHECK(reported >= 0),
            folders INTEGER NOT NULL CHECK(folders >= 0),
            skipped INTEGER NOT NULL CHECK(skipped >= 0),
            body_truncated INTEGER NOT NULL CHECK(body_truncated >= 0),
            limited INTEGER NOT NULL CHECK(limited IN (0,1)),
            indexed_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    ''')


def _validate_schema(index: SecureSearchIndex) -> None:
    try:
        version = index._db.execute(
            'SELECT version FROM pstscout_collection_meta WHERE id = 1'
        ).fetchone()
        if version != (COLLECTION_VERSION,):
            raise CollectionError('Index is not a supported M3.3 collection')
    except CollectionError:
        raise
    except Exception:
        raise CollectionError('Index has no valid M3.3 collection schema') from None


def _read_registry(index: SecureSearchIndex) -> list[RegisteredArchive]:
    _validate_schema(index)
    try:
        rows = index._db.execute('''
            SELECT fingerprint, relative_path, bytes, indexed, reported,
                   folders, skipped, body_truncated, limited
            FROM pstscout_archives ORDER BY relative_path
        ''').fetchall()
    except Exception:
        raise CollectionError('Unable to read encrypted archive registry') from None
    return [RegisteredArchive(*r[:8], bool(r[8])) for r in rows]


def _cleanup_stage(stage: Path) -> None:
    """Best effort cleanup of an ENCRYPTED working copy only."""
    for file in (stage, Path(str(stage)+'-journal'),
                 Path(str(stage)+'-wal'), Path(str(stage)+'-shm')):
        try:
            file.unlink(missing_ok=True)
        except OSError:
            pass


def _encrypted_clone(source_index: Path, stage: Path) -> None:
    """Copy already-encrypted SQLCipher bytes, never SQLite plaintext pages."""
    before = source_index.stat()
    with source_index.open('rb') as src, stage.open('xb') as dst:
        digest = hashlib.sha256()
        while chunk := src.read(_COPY_BUFFER):
            dst.write(chunk)
            digest.update(chunk)
        dst.flush()
        os.fsync(dst.fileno())
    after = source_index.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise CollectionError('Source index changed during migration')
    # Detect truncated/corrupt copy before modifying its encrypted schema.
    check = hashlib.sha256()
    with stage.open('rb') as dest:
        while chunk := dest.read(_COPY_BUFFER):
            check.update(chunk)
    if digest.digest() != check.digest():
        raise CollectionError('Encrypted index copy did not verify')


def migrate_legacy(legacy: Path, target: Path, archive: Path,
                   root: Path, index_password: str) -> RegisteredArchive:
    """Create a new v2 collection from M3.2 without rescanning its old PST.

    Requires the original `.pstsc` path to bind old index rows to their source
    fingerprint. Never overwrites or edits the original M3.2 `.scindex` file.
    """
    legacy, target, archive, root = map(Path, (legacy, target, archive, root))
    if not legacy.is_file():
        raise CollectionError('Original M3.2 index is missing')
    if not target.parent.is_dir() or target.exists() or legacy.resolve() == target.resolve():
        raise CollectionError('Choose a new, nonexisting M3.3 index filename')
    if not root.is_dir():
        raise CollectionError('Archive root directory does not exist')
    source_id, rel, size, mtime = _source_info(root, archive)
    stage = target.with_name(target.name + '.building-' + secrets.token_hex(8))
    success = False
    try:
        with SecureSearchIndex(legacy, index_password) as old:
            old_info = old.info()
            if old_info['source_fingerprint'] != source_id:
                raise CollectionError('Original PST does not match the existing M3.2 index')
            if old.count() != old_info['indexed']:
                raise CollectionError('M3.2 index message counts do not agree')
            if old_info['limited']:
                raise CollectionError('Legacy M3.2 index is partial; use the full index')
            old.check_integrity()
        space = shutil.disk_usage(target.parent).free
        if space < legacy.stat().st_size + 16 * 1024 * 1024:
            raise CollectionError('Insufficient free space to clone encrypted index')
        _encrypted_clone(legacy, stage)
        with SecureSearchIndex(stage, index_password) as db:
            _schema(db)
            db._db.execute('''
                INSERT INTO pstscout_archives
                (fingerprint,relative_path,bytes,source_mtime_ns,indexed,
                 reported,folders,skipped,body_truncated,limited)
                VALUES(?,?,?,?,?,?,?,?,?,?)
            ''', (source_id, rel, size, mtime, old_info['indexed'],
                  old_info['reported'], old_info['folders'], old_info['skipped'],
                  old_info['body_truncated'], int(old_info['limited'])))
            db._db.commit()
        with SecureSearchIndex(stage, index_password) as check:
            records = _read_registry(check)
            if len(records) != 1 or records[0].indexed != old_info['indexed']:
                raise CollectionError('Migrated archive registry failed verification')
            if check.count() != records[0].indexed:
                raise CollectionError('Migrated index message count differs')
            check.check_integrity()
        if target.exists():
            raise CollectionError('M3.3 output appeared during migration')
        if os.name == 'nt':
            # Windows os.rename does not replace a preexisting destination.
            os.rename(stage, target)
        else:
            # On POSIX, os.rename overwrites; exclusive hardlink avoids that.
            os.link(stage, target)
            stage.unlink()
        success = True
        return records[0]
    except (SecureIndexError, OSError) as exc:
        raise CollectionError('Unable to migrate encrypted M3.2 index') from None
    finally:
        if not success:
            _cleanup_stage(stage)


def add_archive(index_path: Path, root: Path, archive: Path, index_password: str,
                archive_password: str, *, max_messages: int = 0,
                body_cap: int = 65536) -> tuple[str, RegisteredArchive | None]:
    """Index only one NEW source atomically; do not touch other archives.

    Returns 'added', 'already_indexed' or 'relocated'. Existing source ID
    normally avoids reading PST bodies entirely.
    """
    if max_messages != 0 or not 1 <= body_cap <= 1048576:
        raise ValueError('M3.3 only registers complete scans (max_messages=0)')
    source_id, rel, size, mtime = _source_info(Path(root), Path(archive))
    try:
        with SecureSearchIndex(index_path, index_password) as db:
            records = _read_registry(db)
            by_id = {x.fingerprint: x for x in records}
            by_path = {x.relative_path.casefold(): x for x in records}
            if source_id in by_id:
                entry = by_id[source_id]
                if rel != entry.relative_path and rel.casefold() not in by_path:
                    # A second copy is not a rename while the old path exists.
                    old_path = Path(root) / Path(entry.relative_path)
                    if not old_path.exists():
                        db._db.execute('UPDATE pstscout_archives SET relative_path=?,bytes=?,source_mtime_ns=? WHERE fingerprint=?',
                                       (rel, size, mtime, source_id))
                        db._db.commit()
                        return 'relocated', entry
                return 'already_indexed', entry
            if rel.casefold() in by_path:
                raise CollectionError('Existing archive path has changed contents; replacement requires M3.4')
            # Nested SAVEPOINT inside an outer transaction: the message stream
            # and registry record commit together. Crash/interruption rolls
            # back BOTH, keeping all previous PSTs searchable.
            db._db.execute('BEGIN IMMEDIATE')
            try:
                summary = db.build(
                    iter_messages(Path(archive), archive_password,
                                  limit=max_messages, show_body=True,
                                  body_cap=body_cap), archive_id=source_id)
                if summary.indexed != summary.messages_reported or summary.duplicate:
                    raise CollectionError('Unexpected duplicate message identifiers in the new archive')
                # A PST archive may be copied or replaced while indexing it.
                latest = _source_info(Path(root), Path(archive))
                if latest[0] != source_id or latest[2] != size or latest[3] != mtime:
                    raise CollectionError('Source archive changed during indexing')
                db._db.execute('''
                    INSERT INTO pstscout_archives
                    (fingerprint,relative_path,bytes,source_mtime_ns,indexed,
                     reported,folders,skipped,body_truncated,limited)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                ''', (source_id, rel, size, mtime, summary.indexed,
                      summary.messages_reported, summary.folders_reported,
                      summary.skipped_reported, summary.body_truncated,
                      int(summary.limited)))
                db._db.commit()
            except Exception:
                db._db.rollback()
                raise
            entry = RegisteredArchive(source_id, rel, size, summary.indexed,
                                      summary.messages_reported, summary.folders_reported,
                                      summary.skipped_reported, summary.body_truncated,
                                      summary.limited)
            return 'added', entry
    except (SecureIndexError, OSError):
        raise CollectionError('Encrypted index could not be opened or updated') from None


def scan_root(index_path: Path, root: Path, password: str) -> ScanStatus:
    """Compare encrypted registry to .pstsc files; headers only, no PST scan."""
    root = Path(root)
    if not root.is_dir():
        raise CollectionError('Archive root directory does not exist')
    with SecureSearchIndex(index_path, password) as db:
        records = _read_registry(db)
    by_id = {r.fingerprint: r for r in records}
    by_path = {r.relative_path.casefold(): r for r in records}
    locations: dict[str, set[str]] = {}
    unseen: set[str] = set()
    modified: set[str] = set()
    unreadable = 0
    for path in root.rglob('*.pstsc'):
        try:
            if not path.is_file() or path.is_symlink():
                continue
            identity, rel, _, _ = _source_info(root, path)
            if identity in by_id:
                locations.setdefault(identity, set()).add(rel.casefold())
            elif rel.casefold() in by_path:
                modified.add(by_path[rel.casefold()].fingerprint)
            else:
                unseen.add(identity)
        except (OSError, SecureIndexError, CollectionError):
            unreadable += 1
    present = moved = duplicates = 0
    for identity, paths in locations.items():
        expected = by_id[identity].relative_path.casefold()
        if expected in paths:
            present += 1
        else:
            moved += 1
        duplicates += max(0, len(paths) - 1)
    missing = len(set(by_id) - set(locations) - modified)
    return ScanStatus(len(records), present, moved, len(unseen),
                      len(modified), missing, duplicates, unreadable)


def collection_info(index_path: Path, password: str) -> tuple[int, list[RegisteredArchive]]:
    with SecureSearchIndex(index_path, password) as db:
        records = _read_registry(db)
        total = db.count()
        if total != sum(r.indexed for r in records):
            raise CollectionError('Archive registry and indexed message totals differ')
        return total, records
