"""PSTScout M3.1: VOLATILE in-memory SQLite FTS5 search index.

Security constraints:
- Never creates a plaintext SQLite or journal file, including temporary SQLite
  databases (uses `:memory:` and `PRAGMA temp_store=MEMORY`).
- Never serializes the database to disk or stores mail as plaintext.
- This is NOT M3.2 persistent encrypted search: the index must be rebuilt each
  time the process starts and may be paged out by the OS. Not production-safe.
- Input events must come from the M2.2 encrypted reader or a synthetic fixture.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Iterable, Iterator, Mapping


class IndexErrorM3(RuntimeError):
    """Sanitized search/index error. Never include message content."""


@dataclass(frozen=True)
class BuildSummary:
    indexed: int
    duplicate: int
    body_truncated: int
    messages_reported: int
    folders_reported: int
    skipped_reported: int
    limited: bool


@dataclass(frozen=True)
class SearchHit:
    archive_id: str
    message_id: str
    subject: str
    sender_name: str
    sender_email: str
    sent_at: str
    folder: str
    attachment_count: int
    rank: float


class VolatileSearchIndex:
    """Transient search for M3.1 only. No persistent encryption yet."""

    def __init__(self) -> None:
        self._db = sqlite3.connect(':memory:')
        try:
            self._db.execute('PRAGMA temp_store=MEMORY')
            self._db.execute('PRAGMA journal_mode=MEMORY')
            self._db.execute('PRAGMA secure_delete=ON')
            self._db.executescript('''
                CREATE TABLE mail_metadata (
                    pk INTEGER PRIMARY KEY,
                    archive_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    attachment_count INTEGER NOT NULL,
                    body_truncated INTEGER NOT NULL,
                    UNIQUE (archive_id, message_id)
                );
                CREATE VIRTUAL TABLE mail_fts USING fts5 (
                    archive_id UNINDEXED,
                    message_id UNINDEXED,
                    subject, sender_name, sender_email, recipients,
                    folder, body, attachment_names,
                    tokenize = 'unicode61 remove_diacritics 2'
                );
            ''')
        except sqlite3.Error as exc:
            self._db.close()
            raise IndexErrorM3('SQLite FTS5 is not available in this Python runtime') from None
        self._closed = False

    def __enter__(self) -> 'VolatileSearchIndex':
        return self

    def __exit__(self, exc_type: object, value: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._db.close()
            self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise IndexErrorM3('The in-memory index is closed')

    def count(self) -> int:
        self._check_open()
        return int(self._db.execute('SELECT count(*) FROM mail_metadata').fetchone()[0])

    @staticmethod
    def _field(value: object, cap: int = 262_144) -> str:
        # Bound untrusted PST metadata; don't generate huge in-memory statements.
        return str(value or '')[:cap]

    def _insert(self, event: Mapping[str, object], archive_id: str) -> tuple[bool, bool]:
        ident = str(event.get('identifier') or '')
        if not ident.isdecimal() or len(ident) > 24:
            raise IndexErrorM3('M3 received a message without a valid identifier')
        atts = event.get('attachments') or []
        if not isinstance(atts, list):
            raise IndexErrorM3('M3 received invalid attachment metadata')
        attnames = ' '.join(self._field(a.get('name'), 1024) for a in atts[:10_000] if isinstance(a, dict))
        recipients = event.get('recipients') or []
        if not isinstance(recipients, list):
            raise IndexErrorM3('M3 received invalid recipient metadata')
        sent_at = self._field(event.get('delivery_time') or event.get('submit_time'), 60)
        cur = self._db.execute('''
            INSERT OR IGNORE INTO mail_metadata
                (archive_id, message_id, sent_at, attachment_count, body_truncated)
            VALUES (?, ?, ?, ?, ?)
        ''', (archive_id, ident, sent_at, len(atts), int(bool(event.get('body_truncated')))))
        if cur.rowcount == 0:
            return False, False
        self._db.execute('''
            INSERT INTO mail_fts (
                rowid, archive_id, message_id, subject, sender_name, sender_email,
                recipients, folder, body, attachment_names
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cur.lastrowid, archive_id, ident,
            self._field(event.get('subject'), 16_384),
            self._field(event.get('sender_name'), 8_192),
            self._field(event.get('sender_email'), 8_192),
            self._field(' '.join(map(str, recipients)), 65_536),
            self._field(event.get('folder_path'), 16_384),
            self._field(event.get('body'), 1_048_576),
            attnames[:262_144],
        ))
        return True, bool(event.get('body_truncated'))

    def build(self, events: Iterable[Mapping[str, object]], *, archive_id: str) -> BuildSummary:
        """Index one archive atomically; no partial index after reader errors.

        Must receive exactly one terminal summary. An abnormal end is an error.
        A normal, limited scan is permitted but explicitly reported as such.
        """
        self._check_open()
        if not archive_id or len(archive_id) > 128 or any(c in archive_id for c in '\r\n\x00'):
            raise ValueError('archive_id must be a short local identifier')
        indexed = duplicate = truncated = total_events = 0
        summary: Mapping[str, object] | None = None
        # One savepoint per build, so a parser failure cannot leave an incomplete
        # archive silently searchable. The only DB is in RAM.
        self._db.execute('SAVEPOINT m3_build')
        try:
            for event in events:
                if not isinstance(event, dict):
                    raise IndexErrorM3('Unexpected PST event type')
                kind = event.get('type')
                if kind == 'message':
                    if summary is not None:
                        raise IndexErrorM3('PST helper emitted a message after summary')
                    total_events += 1
                    added, cut = self._insert(event, archive_id)
                    indexed += int(added)
                    duplicate += int(not added)
                    truncated += int(cut)
                elif kind == 'summary' and summary is None:
                    summary = event
                else:
                    raise IndexErrorM3('Unexpected PST event in index stream')
            if summary is None or total_events != int(summary.get('messages', -1)):
                raise IndexErrorM3('Incomplete PST scan; in-memory index changes rolled back')
            self._db.execute('RELEASE SAVEPOINT m3_build')
            return BuildSummary(indexed, duplicate, truncated,
                                int(summary['messages']), int(summary.get('folders', 0)),
                                int(summary.get('skipped', 0)), bool(summary.get('limited', False)))
        except Exception:
            self._db.execute('ROLLBACK TO SAVEPOINT m3_build')
            self._db.execute('RELEASE SAVEPOINT m3_build')
            raise

    def search(self, phrase: str, *, max_results: int = 20,
               archive_id: str | None = None, earliest: str | None = None,
               latest: str | None = None) -> list[SearchHit]:
        """Literal whole-phrase search; no user supplied SQL or FTS operators."""
        self._check_open()
        phrase = phrase.strip()
        if not phrase or len(phrase) > 500 or not 1 <= max_results <= 100:
            raise ValueError('Invalid phrase or result limit')
        # FTS query remains a literal phrase, not grammar provided by the user.
        fts_phrase = '"' + phrase.replace('"', '""') + '"'
        filters = ['mail_fts MATCH ?']
        params: list[object] = [fts_phrase]
        if archive_id:
            filters.append('m.archive_id = ?')
            params.append(archive_id)
        if earliest:
            filters.append('substr(m.sent_at,1,10) >= ?')
            params.append(earliest)
        if latest:
            filters.append('substr(m.sent_at,1,10) <= ?')
            params.append(latest)
        params.append(max_results)
        try:
            rows = self._db.execute(f'''
                SELECT m.archive_id, m.message_id,
                       f.subject, f.sender_name, f.sender_email, m.sent_at,
                       f.folder, m.attachment_count, bm25(mail_fts) AS rank
                FROM mail_fts AS f
                JOIN mail_metadata AS m ON m.pk = f.rowid
                WHERE {' AND '.join(filters)}
                ORDER BY rank LIMIT ?
            ''', params).fetchall()
        except sqlite3.Error:
            raise IndexErrorM3('Search failed; check query characters or SQLite FTS5 support') from None
        return [SearchHit(*row) for row in rows]
