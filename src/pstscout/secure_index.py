"""M3.2 preview: persistent SQLCipher FTS5 index, encrypted from first page.

Never falls back to stdlib sqlite3 for file-backed connections. Only synthetic
or properly authorized archives should be used while this is not audited.
"""
from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
from typing import Any

from .search_index import BuildSummary, IndexErrorM3, VolatileSearchIndex


SCHEMA_VERSION = 1


class SecureIndexError(RuntimeError):
    """Error whose text is safe to show (must never interpolate source data)."""


def _password_check(password: str) -> None:
    if not isinstance(password, str) or not 16 <= len(password.encode('utf-8')) <= 1024:
        raise SecureIndexError('Use a password of 16-1024 UTF-8 bytes')
    if '\x00' in password or '\r' in password or '\n' in password:
        raise SecureIndexError('Password contains unsupported control characters')


def _cipher_module() -> Any:
    try:
        module = importlib.import_module('sqlcipher3')
    except ImportError:
        raise SecureIndexError('SQLCipher is required; install sqlcipher3==0.6.4') from None
    return module


def source_fingerprint(archive: Path) -> str:
    """In M3.2, identify a .pstsc *container* without persisting its pathname.

    NOT a checksum of the full archive (M3.3 must validate file contents).
    """
    archive = Path(archive)
    if not archive.is_file() or archive.suffix.lower() != '.pstsc':
        raise SecureIndexError('Encrypted PST archive was not found')
    with archive.open('rb') as handle:
        header = handle.read(128)
    if len(header) < 64:
        raise SecureIndexError('Encrypted PST archive has a truncated header')
    digest = hashlib.sha256()
    digest.update(b'PSTScout-M3.2-source-v1\x00')
    digest.update(header)
    digest.update(archive.stat().st_size.to_bytes(8, 'big'))
    return digest.hexdigest()


class SecureSearchIndex(VolatileSearchIndex):
    """Reuse M3.1 insertion/search logic with a SQLCipher-backed connection.

    An instance is valid only with a real SQLCipher library; any unsupported
    cipher or damaged/wrong-password database results in a closed handle.
    """

    def __init__(self, database_path: Path, password: str, *, create: bool = False):
        _password_check(password)
        database_path = Path(database_path)
        if not database_path.parent.is_dir():
            raise SecureIndexError('Index directory does not exist')
        if create and database_path.exists():
            raise SecureIndexError('Index output already exists')
        if not create and not database_path.is_file():
            raise SecureIndexError('Encrypted index was not found')

        dbapi = _cipher_module()
        self._closed = True
        self._db = None
        try:
            self._db = dbapi.connect(str(database_path), timeout=30)
            # PRAGMA does not accept SQL bind parameters. Quote a single SQL
            # literal, never print or log it; double single quotes correctly.
            escaped = password.replace("'", "''")
            self._db.execute("PRAGMA key = '" + escaped + "'")
            row = self._db.execute('PRAGMA cipher_version').fetchone()
            if not row or not row[0] or not str(row[0]).startswith('4.'):
                raise SecureIndexError('A supported SQLCipher 4 runtime is required')
            self._db.execute('PRAGMA cipher_memory_security = ON')
            self._db.execute('PRAGMA temp_store=MEMORY')
            # SQLCipher-encrypted rollback journaling, no persistent WAL.
            self._db.execute('PRAGMA journal_mode=DELETE')
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.execute('PRAGMA secure_delete=ON')
            # Trigger page access to reject wrong passphrases before operations.
            self._db.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
            if create:
                self._create_schema()
            else:
                self._require_schema()
            self._closed = False
        except SecureIndexError:
            if self._db is not None:
                self._db.close()
            raise
        except Exception:
            if self._db is not None:
                self._db.close()
            raise SecureIndexError('Unable to open or unlock SQLCipher index') from None

    def _create_schema(self) -> None:
        # Keep in sync with M3.1's columns. Intentional separate module:
        # M3.1's in-memory creation and tests remain unchanged.
        self._db.executescript('''
            CREATE TABLE mail_metadata (
                pk INTEGER PRIMARY KEY,
                archive_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                attachment_count INTEGER NOT NULL,
                body_truncated INTEGER NOT NULL,
                UNIQUE(archive_id, message_id)
            );
            CREATE VIRTUAL TABLE mail_fts USING fts5 (
                archive_id UNINDEXED,
                message_id UNINDEXED,
                subject, sender_name, sender_email, recipients,
                folder, body, attachment_names,
                tokenize = 'unicode61 remove_diacritics 2'
            );
            CREATE TABLE pstscout_info (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                schema_version INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('building', 'complete')),
                source_fingerprint TEXT NOT NULL,
                indexed_messages INTEGER NOT NULL,
                reported_messages INTEGER NOT NULL,
                skipped INTEGER NOT NULL,
                body_truncated INTEGER NOT NULL,
                limited INTEGER NOT NULL,
                folders INTEGER NOT NULL
            );
        ''')
        self._db.commit()

    def _require_schema(self) -> None:
        row = self._db.execute('''
            SELECT schema_version, status
            FROM pstscout_info WHERE id = 1
        ''').fetchone()
        if row is None or row[0] != SCHEMA_VERSION or row[1] != 'complete':
            raise SecureIndexError('Index is incomplete or uses an unsupported schema')

    def finalize(self, summary: BuildSummary, source_id: str) -> None:
        self._check_open()
        if not (isinstance(source_id, str) and len(source_id) == 64 and
                all(c in '0123456789abcdef' for c in source_id)):
            raise SecureIndexError('Invalid source fingerprint')
        if self.count() != summary.indexed or summary.indexed + summary.duplicate != summary.messages_reported:
            raise SecureIndexError('Indexed message totals are inconsistent')
        try:
            with self._db:
                self._db.execute('''
                    INSERT INTO pstscout_info (
                        id, schema_version, status, source_fingerprint,
                        indexed_messages, reported_messages, skipped,
                        body_truncated, limited, folders
                    ) VALUES (1, ?, 'complete', ?, ?, ?, ?, ?, ?, ?)
                ''', (SCHEMA_VERSION, source_id, summary.indexed,
                      summary.messages_reported, summary.skipped_reported,
                      summary.body_truncated, int(summary.limited),
                      summary.folders_reported))
        except Exception:
            raise SecureIndexError('Unable to finish encrypted index metadata') from None

    def info(self) -> dict:
        self._check_open()
        row = self._db.execute('''
            SELECT source_fingerprint, indexed_messages, reported_messages,
                   skipped, body_truncated, limited, folders
            FROM pstscout_info WHERE id = 1 AND status = 'complete'
        ''').fetchone()
        if not row:
            raise SecureIndexError('Encrypted index has no complete scan')
        return dict(zip(('source_fingerprint', 'indexed', 'reported',
                         'skipped', 'body_truncated', 'limited', 'folders'), row))

    def check_integrity(self) -> int:
        """SQLCipher authenticated-page check + SQLite logical check."""
        self._check_open()
        try:
            failures = self._db.execute('PRAGMA cipher_integrity_check').fetchall()
            if failures:
                raise SecureIndexError('Encrypted index failed page integrity check')
            row = self._db.execute('PRAGMA integrity_check').fetchone()
            if row != ('ok',):
                raise SecureIndexError('Encrypted index failed logical integrity check')
            return self.count()
        except SecureIndexError:
            raise
        except Exception:
            raise SecureIndexError('Unable to verify encrypted index integrity') from None

    def search(self, *args, **kwargs):
        try:
            return super().search(*args, **kwargs)
        except (ValueError, IndexErrorM3):
            raise
        except Exception:
            # sqlcipher3.Error is not sqlite3.Error used by M3.1.
            raise SecureIndexError('Encrypted index query failed') from None

    def close(self) -> None:
        if not getattr(self, '_closed', True):
            self._db.close()
            self._closed = True
