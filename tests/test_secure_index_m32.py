"""M3.2 unit tests use synthetic email events only.

The FakeCipher backend below is for isolated control-flow tests and DOES NOT
implement encryption. A separate conditional test uses genuine SQLCipher and
must run on the user's Windows computer after installing sqlcipher3.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from pstscout import secure_index, persistent_cli
from pstscout.secure_index import SecureIndexError, SecureSearchIndex, source_fingerprint


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
    def fetchone(self):
        return self.rows[0] if self.rows else None
    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, conn):
        self.conn = conn
        self.key_received = None
    def execute(self, sql, *params):
        if sql.startswith('PRAGMA key ='):
            self.key_received = sql
            return FakeCursor([])
        if sql == 'PRAGMA cipher_version':
            return FakeCursor([('4.test-only',)])
        if sql == 'PRAGMA cipher_integrity_check':
            return FakeCursor([])
        if sql == 'PRAGMA cipher_memory_security = ON':
            return FakeCursor([])
        return self.conn.execute(sql, *params)
    def __getattr__(self, name):
        return getattr(self.conn, name)
    def __enter__(self):
        self.conn.__enter__()
        return self
    def __exit__(self, *args):
        return self.conn.__exit__(*args)


class FakeSqlcipher:
    @staticmethod
    def connect(path, timeout=30):
        return FakeConnection(sqlite3.connect(path, timeout=timeout))


@pytest.fixture
def fake_cipher(monkeypatch):
    monkeypatch.setattr(secure_index, '_cipher_module', lambda: FakeSqlcipher)


def msg(ident='17', body='Örnek kurulum raporu'):
    return {'type': 'message', 'identifier': ident, 'subject': 'Şebeke kurulum',
            'sender_name': 'Test Ad', 'sender_email': 'test@example.invalid',
            'folder_path': 'Inbox', 'delivery_time': '2026-01-02',
            'recipients': [], 'attachments': [], 'body': body}


def events(*messages):
    yield from messages
    yield {'type': 'summary', 'messages': len(messages), 'folders': 2,
           'skipped': 0, 'limited': False}


def test_fake_backend_reopen_and_search(fake_cipher, tmp_path):
    path = tmp_path/'encrypted-index.test'
    with SecureSearchIndex(path, "secret'is-larger-than-16", create=True) as idx:
        assert idx._db.key_received == "PRAGMA key = 'secret''is-larger-than-16'"
        summary = idx.build(events(msg()), archive_id='a'*64)
        idx.finalize(summary, 'a'*64)
        assert idx.count() == 1
    with SecureSearchIndex(path, 'long-enough-passphrase') as idx:
        assert idx.info()['indexed'] == 1
        assert idx.search('kurulum')[0].message_id == '17'
        assert idx.check_integrity() == 1
    # Fake backend outputs plaintext SQLite; never mistake it for encryption.
    assert path.read_bytes().startswith(b'SQLite format 3\0')


def test_bad_schema_rejected(fake_cipher, tmp_path):
    path = tmp_path/'db.dat'
    with SecureSearchIndex(path, 'long-enough-password', create=True):
        pass
    with pytest.raises(SecureIndexError, match='incomplete'):
        SecureSearchIndex(path, 'long-enough-password')


def test_build_failure_rolls_back(fake_cipher, tmp_path):
    path = tmp_path/'db.dat'
    with SecureSearchIndex(path, 'long-enough-password', create=True) as idx:
        def broken():
            yield msg()
            raise ValueError('PRIVATE E-MAIL BODY')
        with pytest.raises(ValueError, match='PRIVATE'):
            idx.build(broken(), archive_id='a'*64)
        assert idx.count() == 0


def test_fingerprint_stability_without_data_leak(tmp_path):
    source = tmp_path/'test.pstsc'
    source.write_bytes(b'A'*200)
    assert source_fingerprint(source) == source_fingerprint(source)
    source.write_bytes(b'B'*200)
    assert len(source_fingerprint(source)) == 64


def test_fingerprint_changes_on_replacement(tmp_path):
    source = tmp_path/'test.pstsc'
    source.write_bytes(b'A'*200)
    before = source_fingerprint(source)
    source.write_bytes(b'B'*200)
    assert before != source_fingerprint(source)


def test_cli_synthetic_build_search_verify(fake_cipher, monkeypatch, tmp_path, capsys):
    archive = tmp_path/'test.pstsc'
    archive.write_bytes(b'X'*200)
    index_path = tmp_path/'test.scindex'
    monkeypatch.setattr(persistent_cli.getpass, 'getpass', lambda _: 'abc123-strong-password')
    monkeypatch.setattr(persistent_cli, 'iter_messages', lambda *args, **kw: events(msg()))
    assert persistent_cli.main(['build', '--archive', str(archive), '--index', str(index_path),
                                '--max-messages', '0']) == 0
    assert index_path.is_file()
    assert 'INDEX SAVED' in capsys.readouterr().out
    monkeypatch.setattr('builtins.input', lambda _: '')
    assert persistent_cli.main(['search', '--index', str(index_path)]) == 0
    assert 'messages=1' in capsys.readouterr().out
    assert persistent_cli.main(['verify', '--index', str(index_path)]) == 0
    assert 'VERIFIED' in capsys.readouterr().out


def test_failed_cli_build_leaves_no_published_index(fake_cipher, monkeypatch, tmp_path, capsys):
    archive = tmp_path/'test.pstsc'
    archive.write_bytes(b'X'*200)
    index_path = tmp_path/'test.scindex'
    monkeypatch.setattr(persistent_cli.getpass, 'getpass', lambda _: 'abc123-strong-password')
    def broken(*args, **kwargs):
        yield msg()
        raise RuntimeError('SECRET BODY')
    monkeypatch.setattr(persistent_cli, 'iter_messages', broken)
    assert persistent_cli.main(['build', '--archive', str(archive), '--index', str(index_path)]) == 1
    assert not index_path.exists()
    assert not list(tmp_path.glob('*.building-*'))
    assert 'SECRET BODY' not in capsys.readouterr().out


def test_invalid_password_length_rejected(fake_cipher, tmp_path):
    with pytest.raises(SecureIndexError):
        SecureSearchIndex(tmp_path/'index', 'short', create=True)


def test_output_exists_no_overwrite(fake_cipher, monkeypatch, tmp_path):
    archive = tmp_path/'test.pstsc'
    archive.write_bytes(b'A'*200)
    index_path = tmp_path/'existing.scindex'
    index_path.write_bytes(b'KEEP')
    with pytest.raises(SecureIndexError):
        persistent_cli.build(archive, index_path, limit=0, body_cap=1024)
    assert index_path.read_bytes() == b'KEEP'


@pytest.mark.skipif(__import__('importlib').util.find_spec('sqlcipher3') is None,
                    reason='Install real sqlcipher3 to run mandatory encryption test')
def test_real_sqlcipher_encrypted_at_rest(tmp_path):
    """Required Windows acceptance test: no standard SQLite or plaintext leak."""
    db = tmp_path/'real.scindex'
    password = 'encryption-test-password!'
    with SecureSearchIndex(db, password, create=True) as idx:
        summary = idx.build(events(msg(body='PRIVATE_MARKER_4db5f79e')),
                            archive_id='a'*64)
        idx.finalize(summary, 'a'*64)
    raw = db.read_bytes()
    assert not raw.startswith(b'SQLite format 3\0')
    assert b'PRIVATE_MARKER_4db5f79e' not in raw
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(str(db)).execute('SELECT * FROM mail_metadata').fetchall()
    with pytest.raises(SecureIndexError):
        SecureSearchIndex(db, 'incorrect-test-password')
    with SecureSearchIndex(db, password) as idx:
        assert idx.check_integrity() == 1
        assert idx.search('PRIVATE_MARKER_4db5f79e')
