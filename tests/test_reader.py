"""M1 tests: fake `pst-extractor` simulates a PST in process, never real mail.

These validate Python/Node integration. A REAL PST acceptance test must be
run by the user separately before M1 can be considered production-valid.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from pstscout.reader import (
    PSTReader, MessageInfo, ScanSummary, PSTReaderError, AttachmentLimitExceeded
)

NODE = shutil.which('node')


@pytest.fixture()
def fake_helper(tmp_path: Path) -> tuple[PSTReader, Path]:
    if not NODE:
        pytest.skip('Node is unavailable')
    here = Path(__file__).resolve().parents[1] / 'src' / 'pstscout' / 'node'
    scripts = tmp_path / 'helper'
    scripts.mkdir()
    shutil.copy2(here / 'inspect.mjs', scripts / 'inspect.mjs')
    shutil.copy2(here / 'attachment.mjs', scripts / 'attachment.mjs')
    (scripts / 'package.json').write_text('{"type":"module"}', encoding='utf-8')
    pst_module = scripts / 'node_modules' / 'pst-extractor'
    pst_module.mkdir(parents=True)
    (pst_module / 'package.json').write_text(
        '{"name":"pst-extractor","type":"module","exports":"./index.js"}', encoding='utf-8')
    (pst_module / 'index.js').write_text('''
import fs from 'node:fs';
class Folder {
  constructor(obj) { this.data = obj; this.displayName = obj.name;
    this.contentCount = (obj.messages || []).length; this._i = 0; }
  getNextChild() {
    const obj = this.data.messages[this._i++];
    if (obj.failRead) throw new Error('secret-exception-message');
    if (obj.empty) return null;
    return new Message(obj);
  }
  getSubFolders() {
    if (this.data.failFolderRead) throw new Error('secret-folder-error');
    return (this.data.folders || []).map(x => new Folder(x));
  }
  get hasSubfolders() {
    if (this.data.failSubfolderHint) throw new Error('secret-hint-error');
    if (typeof this.data.hasSubfolders === 'boolean') return this.data.hasSubfolders;
    return (this.data.folders || []).length > 0;
  }
}
class Message {
  constructor(obj) { this.data = obj; this.descriptorNodeId = {toString: () => obj.id};
    this.subject = obj.subject; this.senderName = obj.sender;
    this.senderEmailAddress = obj.email; this.transportMessageHeaders = obj.headers;
    this.messageDeliveryTime = new Date(obj.date); this.clientSubmitTime = new Date(obj.date);
    this.body = obj.body; this.bodyHTML = obj.html || '';
    this.numberOfAttachments = (obj.attachments || []).length;
  }
  getAttachment(index) {
    const obj = this.data.attachments[index];
    let first = true;
    return {longFilename: obj.name, filename: obj.name, filesize: obj.data.length,
      fileInputStream: { read: buffer => {
        if (!first) return 0;
        first = false;
        return buffer.write(obj.data, 0, 'utf8');
      }}};
  }
}
export class PSTFile {
  constructor(path) { this.data = JSON.parse(fs.readFileSync(path, 'utf8')); }
  getRootFolder() { return new Folder(this.data); }
  getDescriptorIndexNode(id) {
    const objects = [...(this.data.messages || [])];
    const recurse = x => {
      for (const f of (x.folders || [])) {
        objects.push(...(f.messages || [])); recurse(f);
      }
    }; recurse(this.data);
    return objects.find(x => x.id === String(id));
  }
  close() {}
}
export class PSTMessage extends Message {
  constructor(pst, descriptor) { if (!descriptor) throw Error('missing'); super(descriptor); }
}
''', encoding='utf-8')
    long_module = scripts / 'node_modules' / 'long'
    long_module.mkdir()
    (long_module / 'package.json').write_text(
        '{"name":"long","type":"module","exports":"./index.js"}', encoding='utf-8')
    (long_module / 'index.js').write_text('export default {fromString: x => x};', encoding='utf-8')
    pst = tmp_path / 'test.pst'
    pst.write_text(json.dumps({
        'name': 'Root', 'messages': [], 'folders': [{
            'name': 'Inbox', 'messages': [{
                'id': '123456789098765', 'subject': 'Deneme İpek', 'sender': 'Demo',
                'email': 'demo@example.test', 'headers': 'To: user@example.test\\r\\nCc: another@example.test',
                'date': '2025-03-04T09:02:00Z', 'body': 'Gizli olmayan test metni',
                'attachments': [{'name': 'demo.txt', 'data': 'hello world'}]
            }], 'folders': []
        }]
    }), encoding='utf-8')
    return PSTReader(node_executable=NODE, scripts_dir=scripts), pst


def test_doctor_missing_executable(tmp_path: Path):
    reader = PSTReader(node_executable=tmp_path/'missing-node.exe', scripts_dir=tmp_path)
    ok, reason = reader.doctor()
    assert not ok
    assert 'Node' in reason


def test_doctor_missing_library(tmp_path: Path):
    reader = PSTReader(node_executable=NODE or 'missing', scripts_dir=tmp_path)
    ok, _ = reader.doctor()
    assert not ok


def test_metadata_read(fake_helper):
    reader, pst = fake_helper
    records = list(reader.events(pst, limit=20))
    assert isinstance(records[0], MessageInfo)
    item = records[0]
    assert item.identifier == '123456789098765'
    assert item.subject == 'Deneme İpek'
    assert item.sender_email == 'demo@example.test'
    assert 'Inbox' in item.folder_path
    assert item.body == ''
    assert item.attachments[0].name == 'demo.txt'
    assert isinstance(records[-1], ScanSummary)
    assert records[-1].messages == 1
    assert records[-1].folders == 2
    assert records[-1].skipped == 0
    assert not records[-1].limited


def test_explicit_body_preview(fake_helper):
    reader, pst = fake_helper
    events = list(reader.events(pst, include_body=True, body_cap=8))
    assert events[0].body == 'Gizli ol'
    assert events[0].body_truncated


def test_attachment_stream_probe(fake_helper):
    reader, pst = fake_helper
    result = reader.attachment_probe(pst, '123456789098765', 0)
    assert result.bytes_read == 11
    assert result.sha256 == __import__('hashlib').sha256(b'hello world').hexdigest()


def test_attachment_limit(fake_helper):
    reader, pst = fake_helper
    with pytest.raises(AttachmentLimitExceeded):
        reader.attachment_probe(pst, '123456789098765', 0, max_bytes=4)


def test_bad_attachment_id(fake_helper):
    reader, pst = fake_helper
    with pytest.raises(ValueError):
        reader.attachment_probe(pst, '../bad', 0)


def test_missing_pst(fake_helper):
    reader, pst = fake_helper
    with pytest.raises(FileNotFoundError):
        list(reader.events(pst.parent/'no.pst'))


def test_bad_body_cap(fake_helper):
    reader, pst = fake_helper
    with pytest.raises(ValueError):
        list(reader.events(pst, body_cap=0))


def test_invalid_pst_content_is_rejected(fake_helper):
    reader, pst = fake_helper
    pst.write_bytes(b'broken source content')
    with pytest.raises(PSTReaderError):
        list(reader.events(pst))


def test_command_line_count_only(fake_helper, capsys, monkeypatch):
    from pstscout import cli
    reader, pst = fake_helper
    monkeypatch.setattr(cli, 'PSTReader', lambda: reader)
    assert cli.main(['inspect', '--pst', str(pst), '--limit', '0', '--count-only']) == 0
    out = capsys.readouterr().out
    assert 'SUMMARY messages=1' in out
    assert 'Deneme İpek' not in out


def test_cli_probe_attachment(fake_helper, capsys, monkeypatch):
    from pstscout import cli
    reader, pst = fake_helper
    monkeypatch.setattr(cli, 'PSTReader', lambda: reader)
    assert cli.main(['attachment-probe', '--pst', str(pst), '--message-id',
                     '123456789098765', '--index', '0']) == 0
    out = capsys.readouterr().out
    assert '11 bytes' in out
    assert 'SHA256' in out


def test_body_not_kept_in_files(fake_helper):
    reader, pst = fake_helper
    list(reader.events(pst, include_body=True))
    # M1 reader only uses pipes; no SQLite DB, extracted attachments or logs.
    assert not list(pst.parent.glob('*.db'))
    assert not list(pst.parent.glob('*.log'))
    assert not list(pst.parent.glob('*.txt'))


def test_skip_diagnostics_classify_without_private_data(fake_helper):
    reader, pst = fake_helper
    data = json.loads(pst.read_text(encoding='utf-8'))
    inbox = data['folders'][0]
    inbox['messages'].extend([
        {'id': 'broken-id', 'subject': 'PRIVATE SUBJECT', 'sender': 'Sensitive Sender'},
        {'failRead': True, 'id': '999', 'subject': 'PRIVATE READ ERROR'},
        {'empty': True, 'id': '998', 'subject': 'PRIVATE EMPTY'},
    ])
    inbox['failFolderRead'] = True
    pst.write_text(json.dumps(data), encoding='utf-8')
    events = list(reader.events(pst, limit=0))
    summary = events[-1]
    assert isinstance(summary, ScanSummary)
    assert summary.messages == 1
    assert summary.skipped == 4
    assert summary.skipped_by_reason == {
        'message_read_error': 1,
        'empty_message': 1,
        'invalid_identifier': 1,
        'message_processing_error': 0,
        'folder_read_error': 1,
    }
    assert summary.folder_error_hints == {
        'no_subfolders': 1, 'subfolders_expected': 0, 'unknown': 0,
    }


def test_cli_count_only_skip_reasons_dont_leak_private_data(fake_helper, capsys, monkeypatch):
    from pstscout import cli
    reader, pst = fake_helper
    data = json.loads(pst.read_text(encoding='utf-8'))
    data['folders'][0]['messages'].append({'id': 'bad-id', 'subject': 'PRIVATE TITLE'})
    pst.write_text(json.dumps(data), encoding='utf-8')
    monkeypatch.setattr(cli, 'PSTReader', lambda: reader)
    assert cli.main(['inspect', '--pst', str(pst), '--limit', '0', '--count-only']) == 0
    out = capsys.readouterr().out
    assert 'skipped=1' in out
    assert 'SKIP_REASONS ' in out
    assert 'invalid_identifier=1' in out
    assert 'PRIVATE TITLE' not in out
    assert 'bad-id' not in out


def test_folder_audit_true_expected_hint(fake_helper):
    reader, pst = fake_helper
    data = json.loads(pst.read_text(encoding='utf-8'))
    data['folders'][0]['failFolderRead'] = True
    data['folders'][0]['hasSubfolders'] = True
    pst.write_text(json.dumps(data), encoding='utf-8')
    summary = list(reader.events(pst, limit=0))[-1]
    assert summary.skipped_by_reason['folder_read_error'] == 1
    assert summary.folder_error_hints == {
        'no_subfolders': 0, 'subfolders_expected': 1, 'unknown': 0,
    }


def test_folder_audit_unknown_hint(fake_helper):
    reader, pst = fake_helper
    data = json.loads(pst.read_text(encoding='utf-8'))
    data['folders'][0]['failFolderRead'] = True
    data['folders'][0]['failSubfolderHint'] = True
    pst.write_text(json.dumps(data), encoding='utf-8')
    summary = list(reader.events(pst, limit=0))[-1]
    assert summary.folder_error_hints == {
        'no_subfolders': 0, 'subfolders_expected': 0, 'unknown': 1,
    }


def test_cli_folder_audit_has_no_private_fields(fake_helper, monkeypatch, capsys):
    from pstscout import cli
    reader, pst = fake_helper
    data = json.loads(pst.read_text(encoding='utf-8'))
    data['folders'][0]['failFolderRead'] = True
    data['folders'][0]['name'] = 'PRIVATEFOLDER123'
    pst.write_text(json.dumps(data), encoding='utf-8')
    monkeypatch.setattr(cli, 'PSTReader', lambda: reader)
    assert cli.main(['inspect', '--pst', str(pst), '--limit', '0', '--count-only']) == 0
    out = capsys.readouterr().out
    assert 'FOLDER_ERROR_HINTS no_subfolders=1 subfolders_expected=0 unknown=0' in out
    assert 'PRIVATEFOLDER123' not in out
    assert 'secret-folder-error' not in out
