"""M3.1 FTS5 search tests: synthetic metadata only, no live PST or disk index."""
from __future__ import annotations

import pytest
from pstscout.search_index import VolatileSearchIndex, IndexErrorM3


def message(identifier: str, subject: str = 'Şebeke anten optimizasyonu',
            body: str = 'Saha ölçüm raporu', date: str = '2026-02-19T10:00:00Z',
            truncated: bool = False, attname: str = 'teknik-rapor.xlsx') -> dict:
    return {'type':'message','identifier':identifier,'subject':subject,
            'sender_name':'Test Kullanıcı', 'sender_email':'tester@example.invalid',
            'recipients':['To: user@example.invalid'], 'folder_path':'Inbox/Reports',
            'body':body, 'delivery_time':date, 'body_truncated':truncated,
            'attachments':[{'index':0,'name':attname,'size':88}]}


def events(*msgs, skipped=0, limited=False):
    return [*msgs, {'type':'summary', 'messages':len(msgs), 'folders':2,
                    'skipped':skipped, 'limited':limited}]


def test_utf8_subject_and_body_search():
    with VolatileSearchIndex() as db:
        result=db.build(events(message('101')),archive_id='archive-a')
        assert result.indexed==1
        assert db.count()==1
        assert db.search('anten')[0].message_id=='101'
        assert db.search('Saha ölçüm')[0].message_id=='101'
        assert db.search('olmayan')==[]


def test_attachment_name_sender_and_folder_search():
    with VolatileSearchIndex() as db:
        db.build(events(message('11')),archive_id='a')
        assert db.search('teknik')[0].message_id=='11'
        assert db.search('tester')[0].message_id=='11'
        assert db.search('Inbox')[0].message_id=='11'


def test_date_filter():
    with VolatileSearchIndex() as db:
        db.build(events(message('12',date='2025-01-01T00:00:00Z'),
                        message('13',date='2026-03-15T00:00:00Z')),archive_id='a')
        hits=db.search('anten',earliest='2026-01-01')
        assert [x.message_id for x in hits]==['13']
        assert [x.message_id for x in db.search('anten',latest='2025-12-31')]==['12']


def test_duplicate_identifiers_do_not_duplicate_fts():
    with VolatileSearchIndex() as db:
        db.build(events(message('101')),archive_id='a')
        summary=db.build(events(message('101')),archive_id='a')
        assert summary.duplicate==1
        assert summary.indexed==0
        assert len(db.search('anten'))==1


def test_identical_id_different_archive_distinct():
    with VolatileSearchIndex() as db:
        db.build(events(message('22')),archive_id='a')
        db.build(events(message('22')),archive_id='b')
        assert len(db.search('anten'))==2
        assert len(db.search('anten',archive_id='a'))==1


def test_fts_operator_characters_are_not_executed():
    with VolatileSearchIndex() as db:
        db.build(events(message('7',subject='Alpha NEAR Beta')),archive_id='a')
        # Literal phrase, not a syntax expression or SQL fragment.
        assert db.search('Alpha NEAR Beta')[0].message_id=='7'
        assert db.search('Alpha OR Something') == []
        assert db.search('"; DROP TABLE mail_metadata; --') == []
        assert db.count()==1


def test_reader_failure_rolls_back():
    with VolatileSearchIndex() as db:
        db.build(events(message('1')),archive_id='a')
        def broken():
            yield message('2')
            raise RuntimeError('private source body')
        with pytest.raises(RuntimeError):
            db.build(broken(),archive_id='a')
        assert db.count()==1
        assert db.search('anten')[0].message_id=='1'


def test_summary_missing_rolls_back():
    with VolatileSearchIndex() as db:
        with pytest.raises(IndexErrorM3):
            db.build([message('2')],archive_id='a')
        assert db.count()==0


def test_message_count_mismatch_rolls_back():
    with VolatileSearchIndex() as db:
        with pytest.raises(IndexErrorM3):
            db.build([message('2'), {'type':'summary','messages':99}],archive_id='a')
        assert db.count()==0


def test_truncation_and_skipped_marked():
    with VolatileSearchIndex() as db:
        result=db.build(events(message('1',truncated=True),skipped=4,limited=True),archive_id='a')
        assert (result.body_truncated,result.skipped_reported,result.limited)==(1,4,True)


def test_reject_malicious_identifier():
    with VolatileSearchIndex() as db:
        with pytest.raises(IndexErrorM3):
            db.build(events(message('1;DELETE')),archive_id='a')
        assert db.count()==0


def test_in_memory_db_does_not_create_database_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with VolatileSearchIndex() as db:
        db.build(events(message('1',subject='PRIVATE DEMO VALUE')),archive_id='a')
        assert len(db.search('PRIVATE'))==1
    assert list(tmp_path.iterdir())==[]


def test_closed_database_rejects_queries():
    db=VolatileSearchIndex()
    db.close()
    with pytest.raises(IndexErrorM3):
        db.search('anten')


def test_validating_limits():
    with VolatileSearchIndex() as db:
        with pytest.raises(ValueError):db.search('')
        with pytest.raises(ValueError):db.search('anten',max_results=1000)
        with pytest.raises(ValueError):db.build(events(message('1')),archive_id='a\nb')



def test_search_cli_uses_m2_events_and_prompts(monkeypatch, capsys, tmp_path):
    from pstscout import search_cli
    seen = []
    def fake_iter(archive, password, **kwargs):
        seen.append((archive, password, kwargs))
        yield message('15', subject='Örnek Telsiz Malzeme')
        yield {'type': 'summary', 'messages': 1, 'folders': 1, 'skipped': 0, 'limited': True}
    monkeypatch.setattr(search_cli, 'iter_messages', fake_iter)
    monkeypatch.setattr(search_cli.getpass, 'getpass', lambda _: 'not-written-to-disk')
    values = iter(['Telsiz', ''])
    monkeypatch.setattr('builtins.input', lambda prompt: next(values))
    monkeypatch.chdir(tmp_path)
    result = search_cli.main(['--archive', str(tmp_path/'demo.pstsc'), '--max-messages', '20'])
    assert result == 0
    assert seen[0][1] == 'not-written-to-disk'
    assert seen[0][2]['show_body'] is True
    output=capsys.readouterr().out
    assert 'MATCHES_SHOWN: 1' in output
    assert 'Örnek Telsiz Malzeme' not in output
    assert 'not-written-to-disk' not in output
    assert list(tmp_path.iterdir()) == []


def test_search_cli_rejects_partial_failed_reader(monkeypatch, capsys):
    from pstscout import search_cli
    from pstscout.vault_bridge import BridgeError
    def broken(*args, **kwargs):
        yield message('99')
        raise BridgeError('SENSITIVE FILE NAME')
    monkeypatch.setattr(search_cli, 'iter_messages', broken)
    monkeypatch.setattr(search_cli.getpass, 'getpass', lambda _: 'demo-secret')
    code = search_cli.main(['--archive', 'placeholder.pstsc'])
    assert code == 1
    output=capsys.readouterr().out
    assert 'M3 ERROR' in output
    assert 'SENSITIVE FILE NAME' not in output
