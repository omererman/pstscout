"""Privacy-preserving M3 diagnostics unit tests (no real email data)."""
from __future__ import annotations


def message(identifier, subject='test', body='test'):
    return {
        'type': 'message', 'identifier': identifier, 'subject': subject,
        'body': body, 'sender_name': 'Test', 'sender_email': 'tester@example.invalid',
        'folder_path': 'test', 'recipients': [], 'attachments': [],
        'delivery_time': '2026-10-01T00:00:00Z',
    }


def events(*msgs):
    return [*msgs, {'type': 'summary', 'messages': len(msgs), 'folders': 1,
                    'skipped': 0, 'limited': False}]

def test_diagnostic_bridge_error_does_not_expose_sensitive_body(monkeypatch, capsys):
    from pstscout import search_cli
    from pstscout.vault_bridge import BridgeError
    def broken(*args, **kwargs):
        yield message('123', subject='SENSITIVE ONLY')
        raise BridgeError('SENSITIVE INTERNAL FOLDER / secret path')
    monkeypatch.setattr(search_cli, 'iter_messages', broken)
    monkeypatch.setattr(search_cli.getpass, 'getpass', lambda _: 'secret')
    assert search_cli.main(['--archive', 'mock.pstsc', '--max-messages', '2']) == 1
    out = capsys.readouterr().out
    assert 'M3 ERROR [PST_READER]' in out
    assert 'messages_seen=1' in out and 'summaries_seen=0' in out
    assert 'SENSITIVE' not in out and 'secret' not in out


def test_diagnostic_index_validation_redacts_unknown_error(monkeypatch, capsys):
    from pstscout import search_cli
    monkeypatch.setattr(search_cli.getpass, 'getpass', lambda _: 'password')
    def invalid(*args, **kwargs):
        yield message('NOT_DECIMAL', subject='SENSITIVE SUBJECT')
        yield {'type':'summary', 'messages':1}
    monkeypatch.setattr(search_cli, 'iter_messages', invalid)
    assert search_cli.main(['--archive', 'mock.pstsc']) == 1
    out = capsys.readouterr().out
    assert '[INDEX_VALIDATION]' in out
    assert 'valid identifier' in out
    assert 'SENSITIVE' not in out


def test_metadata_only_skips_body_read(monkeypatch, capsys):
    from pstscout import search_cli
    calls = []
    def fake(*args, **kwargs):
        calls.append(kwargs)
        yield message('55', body='PRIVATE TEXT')
        yield {'type':'summary', 'messages':1, 'folders':1, 'skipped':0, 'limited':False}
    monkeypatch.setattr(search_cli, 'iter_messages', fake)
    monkeypatch.setattr(search_cli.getpass, 'getpass', lambda _: 'password')
    monkeypatch.setattr('builtins.input', lambda _: '')
    assert search_cli.main(['--archive', 'mock.pstsc', '--metadata-only']) == 0
    out = capsys.readouterr().out
    assert calls[0]['show_body'] is False
    assert 'NOT indexed' in out
    assert 'PRIVATE' not in out


def test_sqlite_error_is_sanitized(monkeypatch, capsys):
    import sqlite3
    from pstscout import search_cli
    monkeypatch.setattr(search_cli.getpass, 'getpass', lambda _: 'password')
    monkeypatch.setattr(search_cli, 'iter_messages', lambda *a, **kw: events(message('1')))
    def fake_build(*args, **kwargs):
        raise sqlite3.OperationalError('PRIVATE SUBJECT')
    monkeypatch.setattr(search_cli.VolatileSearchIndex, 'build', fake_build)
    assert search_cli.main(['--archive', 'mock.pstsc']) == 1
    out=capsys.readouterr().out
    assert '[SQLITE]' in out
    assert 'PRIVATE SUBJECT' not in out


def test_unexpected_parser_exception_is_sanitized(monkeypatch, capsys):
    from pstscout import search_cli
    monkeypatch.setattr(search_cli.getpass, 'getpass', lambda _: 'password')
    def bug(*args, **kwargs):
        raise RuntimeError('PRIVATE BODY')
    monkeypatch.setattr(search_cli, 'iter_messages', bug)
    assert search_cli.main(['--archive','mock.pstsc']) == 1
    out = capsys.readouterr().out
    assert '[UNEXPECTED]' in out
    assert 'PRIVATE BODY' not in out
