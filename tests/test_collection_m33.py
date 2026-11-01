"""M3.3 functional tests use synthetic .pstsc headers and a *FAKE* SQLite backend.

The fake below is intentionally NOT encrypted. Never use it for real data.
Run the mandatory SQLCipher test on Windows with the real `sqlcipher3` package.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from pstscout import collection


PASSWORD = 'A-very-long-passphrase-for-testing'


class FakeSecureSearchIndex:
    """Test double for SQLCipher (plaintext in pytest tmp_path only)."""
    def __init__(self, location, password, create=False):
        self.path = Path(location)
        if create and self.path.exists():
            raise RuntimeError('already exists')
        if not create and not self.path.is_file():
            raise RuntimeError('missing')
        self._db = sqlite3.connect(self.path)
        if create:
            self._db.executescript('''
                CREATE TABLE mail_metadata(
                    pk INTEGER PRIMARY KEY, archive_id TEXT NOT NULL,
                    message_id TEXT NOT NULL, sent_at TEXT NOT NULL,
                    attachment_count INTEGER NOT NULL, body_truncated INTEGER NOT NULL,
                    UNIQUE (archive_id,message_id));
                CREATE VIRTUAL TABLE mail_fts USING fts5(
                    archive_id UNINDEXED, message_id UNINDEXED,
                    subject, sender_name, sender_email, recipients, folder, body,
                    attachment_names);
                CREATE TABLE pstscout_info(
                    id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL,
                    status TEXT NOT NULL, source_fingerprint TEXT NOT NULL,
                    indexed_messages INTEGER NOT NULL, reported_messages INTEGER NOT NULL,
                    skipped INTEGER NOT NULL, body_truncated INTEGER NOT NULL,
                    limited INTEGER NOT NULL, folders INTEGER NOT NULL);
            ''')
    def __enter__(self): return self
    def __exit__(self, *args): self._db.close()
    def count(self):
        return self._db.execute('SELECT COUNT(*) FROM mail_metadata').fetchone()[0]
    def info(self):
        data = self._db.execute('''
            SELECT source_fingerprint,indexed_messages,reported_messages,
                   skipped,body_truncated,limited,folders
            FROM pstscout_info WHERE id=1
        ''').fetchone()
        names=['source_fingerprint','indexed','reported','skipped','body_truncated',
               'limited','folders']
        return dict(zip(names,data))
    def check_integrity(self):
        assert self._db.execute('PRAGMA integrity_check').fetchone()==('ok',)
        return self.count()
    def build(self, events, archive_id):
        self._db.execute('SAVEPOINT fake_build')
        indexed=duplicate=truncated=seen=0
        summary=None
        try:
            for item in events:
                if item['type']=='message':
                    if summary is not None: raise RuntimeError('message after summary')
                    seen+=1
                    ident=item['identifier']
                    cur=self._db.execute('''
                        INSERT OR IGNORE INTO mail_metadata
                        (archive_id,message_id,sent_at,attachment_count,body_truncated)
                        VALUES(?,?,?,0,0)
                    ''',(archive_id,ident,'2026-01-01'))
                    if cur.rowcount:
                        indexed+=1
                        self._db.execute('''
                            INSERT INTO mail_fts
                            (rowid,archive_id,message_id,subject,sender_name,
                             sender_email,recipients,folder,body,attachment_names)
                            VALUES(?,?,?,?,?,?,?,?,?,?)
                        ''',(cur.lastrowid,archive_id,ident,item.get('subject',''),
                             '','', '', '',item.get('body',''),''))
                    else: duplicate+=1
                else:
                    summary=item
            if summary is None or summary['messages'] != seen:
                raise RuntimeError('invalid summary')
            self._db.execute('RELEASE SAVEPOINT fake_build')
            return SimpleNamespace(indexed=indexed,duplicate=duplicate,
                messages_reported=seen, folders_reported=summary['folders'],
                skipped_reported=summary['skipped'], body_truncated=truncated,
                limited=summary['limited'])
        except Exception:
            self._db.execute('ROLLBACK TO SAVEPOINT fake_build')
            self._db.execute('RELEASE SAVEPOINT fake_build')
            raise


@pytest.fixture
def fake_db(monkeypatch):
    monkeypatch.setattr(collection, 'SecureSearchIndex', FakeSecureSearchIndex)


def new_archive(root: Path, name: str, marker: bytes) -> Path:
    f=root/name
    f.parent.mkdir(parents=True, exist_ok=True)
    # Stand-in data, not a genuine encrypted archive. Metadata header is distinct.
    f.write_bytes(marker.ljust(2048, b'X'))
    return f


def fake_stream(archive, password, *, limit=0, show_body=True, body_cap=65536):
    # Deterministic synthetic records; same message IDs across distinct PSTs.
    for i in range(2 if limit==0 else min(2,limit)):
        yield {'type':'message','identifier':str(i+1),
               'subject':'Teknik kurulum','body':'Anten test verisi'}
    count=2 if limit==0 else min(2,limit)
    yield {'type':'summary','messages':count,'folders':2,'skipped':0,'limited':bool(limit)}


def seed_legacy(index_path, fingerprint, messages=2):
    with FakeSecureSearchIndex(index_path, PASSWORD,create=True) as db:
        for row_id in range(1,messages+1):
            db._db.execute('''
                INSERT INTO mail_metadata
                (archive_id,message_id,sent_at,attachment_count,body_truncated)
                VALUES(?,?,?,0,0)
            ''',(fingerprint,str(row_id),'2025-01-01'))
            db._db.execute('''
                INSERT INTO mail_fts
                (rowid,archive_id,message_id,subject,sender_name,sender_email,
                 recipients,folder,body,attachment_names)
                VALUES(?,?,?,?,?,?,?,?,?,?)
            ''',(row_id,fingerprint,str(row_id),'Önceki mesaj','','','','','eski içerik',''))
        db._db.execute('''
            INSERT INTO pstscout_info
            (id,schema_version,status,source_fingerprint,indexed_messages,
             reported_messages,skipped,body_truncated,limited,folders)
            VALUES (1,1,'complete',?,?,?,0,0,0,2)
        ''',(fingerprint,messages,messages))
        db._db.commit()


def seed_collection(tmp_path,monkeypatch):
    root=tmp_path/'Mail Arsiv 2';root.mkdir()
    first=new_archive(root,'first.pstsc',b'FIRST_CONTENT')
    fp=collection.source_fingerprint(first)
    legacy=tmp_path/'M3.2.scindex'
    seed_legacy(legacy,fp)
    newer=tmp_path/'M3.3.scindex'
    old_bytes=legacy.read_bytes()
    migrated=collection.migrate_legacy(legacy,newer,first,root,PASSWORD)
    assert old_bytes==legacy.read_bytes()
    return root,first,legacy,newer,migrated


def test_migrate_preserves_existing_index_and_14979_like_rows(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,migrated=seed_collection(tmp_path,monkeypatch)
    assert migrated.relative_path=='first.pstsc'
    assert migrated.indexed==2
    total,records=collection.collection_info(new,PASSWORD)
    assert total==2 and len(records)==1
    assert legacy.is_file() and new.is_file()


def test_append_new_archive_no_rescan_existing(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    second=new_archive(root,'second.pstsc',b'SECOND_CONTENT')
    calls=[]
    def instrument(path,*args,**kw):
        calls.append(Path(path).name)
        yield from fake_stream(path,*args,**kw)
    monkeypatch.setattr(collection,'iter_messages',instrument)
    action,record=collection.add_archive(new,root,second,PASSWORD,'new-pst-password')
    assert action=='added' and record.indexed==2
    assert calls==['second.pstsc']
    total,rows=collection.collection_info(new,PASSWORD)
    assert total==4 and len(rows)==2
    assert sum(x.indexed for x in rows)==4
    action,_=collection.add_archive(new,root,second,PASSWORD,'wrong-password')
    assert action=='already_indexed'
    assert calls==['second.pstsc']


def test_scan_detects_new_and_changed(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    second=new_archive(root,'new.pstsc',b'NEW_CONTENT')
    status=collection.scan_root(new,root,PASSWORD)
    assert status.registered==1 and status.present==1 and status.new==1
    assert status.changed==status.missing==0
    # A replacement at the same path is flagged rather than automatically reindexed.
    first.write_bytes(b'DIFFERENT_HEADER'.ljust(2048,b'X'))
    status=collection.scan_root(new,root,PASSWORD)
    assert status.changed==1 and status.missing==0
    assert status.new==1


def test_rename_updates_relative_path_no_read(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    relocated=root/'renamed.pstsc'
    first.rename(relocated)
    monkeypatch.setattr(collection,'iter_messages',lambda *a,**k: (_ for _ in ()).throw(RuntimeError('must not scan')))
    assert collection.scan_root(new,root,PASSWORD).moved==1
    action,_=collection.add_archive(new,root,relocated,PASSWORD,'unneeded')
    assert action=='relocated'
    assert collection.scan_root(new,root,PASSWORD).present==1
    assert collection.collection_info(new,PASSWORD)[1][0].relative_path=='renamed.pstsc'


def test_clone_does_not_overwrite_and_wrong_source_rejected(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    wrong=new_archive(root,'wrong.pstsc',b'WRONG')
    with pytest.raises(collection.CollectionError,match='does not match'):
        collection.migrate_legacy(legacy,tmp_path/'wrong-new.scindex',wrong,root,PASSWORD)
    with pytest.raises(collection.CollectionError,match='nonexisting'):
        collection.migrate_legacy(legacy,new,first,root,PASSWORD)
    assert not (tmp_path/'wrong-new.scindex').exists()


def test_incremental_failure_rolls_back_all_new_messages(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    second=new_archive(root,'second.pstsc',b'SECOND_CONTENT')
    def broken(*args,**kwargs):
        yield {'type':'message','identifier':'1','subject':'PRIVATE SUBJECT','body':'PRIVATE BODY'}
        raise RuntimeError('SENSITIVE CONTENT')
    monkeypatch.setattr(collection,'iter_messages',broken)
    with pytest.raises(RuntimeError):
        collection.add_archive(new,root,second,PASSWORD,'secret')
    total,rows=collection.collection_info(new,PASSWORD)
    assert total==2 and len(rows)==1
    assert collection.scan_root(new,root,PASSWORD).new==1


def test_identical_source_copies_not_reindexed(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    alias=root/'alias.pstsc'
    shutil.copyfile(first,alias)
    monkeypatch.setattr(collection,'iter_messages',lambda *a,**kw: (_ for _ in ()).throw(RuntimeError('no scan')))
    assert collection.scan_root(new,root,PASSWORD).duplicates==1
    result,_=collection.add_archive(new,root,alias,PASSWORD,'ignored')
    assert result=='already_indexed'
    assert collection.collection_info(new,PASSWORD)[0]==2


def test_reject_archive_outside_root(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    outside=new_archive(tmp_path,'external.pstsc',b'EXTERNAL')
    with pytest.raises(collection.CollectionError,match='inside'):
        collection.add_archive(new,root,outside,PASSWORD,'secret')


def test_scan_does_not_expose_sensitive_content(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    secret_file=new_archive(root,'KURUMSAL_KONU_SECRET.pstsc',b'HEADER_ONLY')
    result=collection.scan_root(new,root,PASSWORD)
    assert result.new==1
    assert 'KURUMSAL' not in repr(result)


def test_migration_cli_error_does_not_expose_raw_exception(monkeypatch, capsys, tmp_path):
    from pstscout import collection_cli
    monkeypatch.setattr(collection_cli, '_input_password', lambda _: 'a-private-password')
    def fail(*args,**kwargs):
        raise RuntimeError('PRIVATE MAIL SUBJECT')
    monkeypatch.setattr(collection_cli, 'migrate_legacy', fail)
    result=collection_cli.main(['migrate','--legacy-index',str(tmp_path/'old.scindex'),
             '--index',str(tmp_path/'new.scindex'),'--archive',str(tmp_path/'a.pstsc'),
             '--root',str(tmp_path)])
    assert result==1
    out=capsys.readouterr().out
    assert 'M3.3 ERROR' in out
    assert 'PRIVATE MAIL SUBJECT' not in out
    assert 'a-private-password' not in out


def test_add_archive_source_changed_rolls_back(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    target=new_archive(root,'new.pstsc',b'SECOND_CONTENT')
    def change(*args,**kwargs):
        yield {'type':'message','identifier':'1','subject':'demo'}
        # Simulate overwrite while streaming.
        target.write_bytes(b'DIFFERENT_HEADER'.ljust(2048,b'Y'))
        yield {'type':'summary','messages':1,'folders':1,'skipped':0,'limited':False}
    monkeypatch.setattr(collection,'iter_messages',change)
    with pytest.raises(collection.CollectionError,match='changed during indexing'):
        collection.add_archive(new,root,target,PASSWORD,'sourcepw')
    assert collection.collection_info(new,PASSWORD)[0]==2


def test_actual_sqlcipher_migration_and_incremental_index(tmp_path, monkeypatch):
    """Mandatory installed-Windows test; proves real encrypted pages, not fake SQLite."""
    pytest.importorskip('sqlcipher3',reason='Install real sqlcipher3 for M3.3 encrypted acceptance')
    from pstscout.secure_index import SecureSearchIndex as RealIndex
    from pstscout.secure_index import source_fingerprint as real_fingerprint
    from pstscout.vault import encrypt_file
    root=tmp_path/'archives'; root.mkdir()
    original_a=root/'first.bin';original_a.write_bytes(b'!BDN'+b'A'*1600)
    archive_a=root/'first.pstsc'
    encrypt_file(original_a,archive_a,PASSWORD)
    original_b=root/'second.bin';original_b.write_bytes(b'!BDN'+b'B'*1600)
    archive_b=root/'second.pstsc'
    encrypt_file(original_b,archive_b,PASSWORD)
    legacy=tmp_path/'original.scindex'
    multi=tmp_path/'multi.scindex'
    fp=real_fingerprint(archive_a)
    with RealIndex(legacy,PASSWORD,create=True) as db:
        summary=db.build(fake_stream(archive_a,'ignored'), archive_id=fp)
        db.finalize(summary,fp)
    legacy_bytes=legacy.read_bytes()
    migrated=collection.migrate_legacy(legacy,multi,archive_a,root,PASSWORD)
    assert migrated.indexed==2
    assert legacy.read_bytes()==legacy_bytes
    assert multi.read_bytes()[:16]!=b'SQLite format 3\0'
    monkeypatch.setattr(collection,'iter_messages',fake_stream)
    state,record=collection.add_archive(multi,root,archive_b,PASSWORD,PASSWORD)
    assert state=='added' and record.indexed==2
    with RealIndex(multi,PASSWORD) as db:
        assert db.count()==4
        assert len(db.search('kurulum'))==4
        assert db.check_integrity()==4
    assert b'Teknik kurulum' not in multi.read_bytes()
    assert collection.scan_root(multi,root,PASSWORD).present==2


def test_add_rejects_replacement_at_same_path(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    first.write_bytes(b'REPLACED_CONTENT'.ljust(2048,b'Y'))
    monkeypatch.setattr(collection,'iter_messages',lambda *a,**kw: (_ for _ in ()).throw(RuntimeError('must not reindex')))
    with pytest.raises(collection.CollectionError,match='changed contents'):
        collection.add_archive(new,root,first,PASSWORD,'ignored')
    assert collection.collection_info(new,PASSWORD)[0]==2


def test_relative_root_survives_drive_like_relocation(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    relocated_root=tmp_path/'DIFFERENT_DRIVE'; relocated_root.mkdir()
    shutil.copy2(first,relocated_root/first.name)
    assert collection.scan_root(new,relocated_root,PASSWORD).present==1


def test_partial_scans_are_not_marked_as_completed(fake_db,tmp_path,monkeypatch):
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    new_source=new_archive(root,'new.pstsc',b'NEW_CONTENT')
    with pytest.raises(ValueError,match='complete scans'):
        collection.add_archive(new,root,new_source,PASSWORD,'unused',max_messages=10)
    assert collection.collection_info(new,PASSWORD)[0]==2


def test_reject_migration_of_partial_legacy_index(fake_db,tmp_path,monkeypatch):
    root=tmp_path/'pst-root';root.mkdir()
    src=new_archive(root,'first.pstsc',b'FIRST_CONTENT')
    old=tmp_path/'partial.scindex'
    seed_legacy(old,collection.source_fingerprint(src))
    with sqlite3.connect(old) as db:
        db.execute('UPDATE pstscout_info SET limited=1')
    target=tmp_path/'multi.scindex'
    with pytest.raises(collection.CollectionError,match='partial'):
        collection.migrate_legacy(old,target,src,root,PASSWORD)
    assert not target.exists()


def test_cli_sync_indexes_only_new_archives(fake_db,tmp_path,monkeypatch,capsys):
    from pstscout import collection_cli
    root,first,legacy,new,_=seed_collection(tmp_path,monkeypatch)
    new_archive(root,'PRIVATE_TITLE_SECOND.pstsc',b'NEW_CONTENT')
    monkeypatch.setattr(collection,'iter_messages',fake_stream)
    monkeypatch.setattr(collection_cli,'SecureSearchIndex',FakeSecureSearchIndex)
    inputs=iter([PASSWORD,'new-archive-password'])
    monkeypatch.setattr(collection_cli,'_input_password',lambda label: next(inputs))
    assert collection_cli.main(['sync','--index',str(new),'--root',str(root)])==0
    output=capsys.readouterr().out
    assert 'new_archives=1' in output
    assert 'archives=2 messages=4' in output
    assert 'PRIVATE_TITLE' not in output
    # second sync cannot re-index known archive
    monkeypatch.setattr(collection_cli,'_input_password',lambda label:PASSWORD)
    assert collection_cli.main(['sync','--index',str(new),'--root',str(root)])==0
    assert 'new_archives=0' in capsys.readouterr().out
