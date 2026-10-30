"""Cross-language M2.2 integration tests with fake pst-extractor.

The fixture simulates a PSTFile class; only user testing with a real PST
can prove interoperability with the actual 1.12.0 parser.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from pstscout.vault import encrypt_file, EncryptedPST
from pstscout import vault_bridge as bridge

NODE = shutil.which('node')


@pytest.fixture
def setup_bridge(tmp_path, monkeypatch):
    if not NODE:
        pytest.skip('Node is not available')
    folder = tmp_path / 'node'
    folder.mkdir()
    module = folder / 'node_modules' / 'pst-extractor'
    module.mkdir(parents=True)
    (module / 'package.json').write_text('{"name":"pst-extractor","type":"commonjs","main":"index.cjs"}')
    (module / 'index.cjs').write_text('''
const fs = require('node:fs');
class PSTFile {
 constructor(name) {
   this._pstFilename = name;
   this.pstFD = fs.openSync(name,'r');
   const hdr = Buffer.alloc(4);
   this.readSync(hdr,4,0);
   if (hdr.toString('ascii') !== '!BDN') throw Error('not a PST');
 }
 readSync(buffer, length, position) {return fs.readSync(this.pstFD, buffer, 0, length, position);}
 close() {fs.closeSync(this.pstFD);}
}
module.exports = {PSTFile};
''')
    hook = Path(__file__).resolve().parents[1] / 'src' / 'pstscout' / 'node' / 'vault_hook.cjs'
    shutil.copy2(hook, folder / 'vault_hook.cjs')
    (folder / 'inspect.mjs').write_text('''
import { PSTFile } from 'pst-extractor';
const f = new PSTFile(process.argv[2]);
const start = Buffer.alloc(5);
f.readSync(start, 5, 0);
console.log(JSON.stringify({type:'message', identifier:'41', folder_path:'Test',
 subject:start.toString('ascii'), sender_name:'Fixture', sender_email:'fixture@example.test',
 attachments:[]}));
console.log(JSON.stringify({type:'summary', messages:1, folders:1, skipped:0, limited:false}));
f.close();
''')
    (folder / 'attachment.mjs').write_text('''
import { PSTFile } from 'pst-extractor';
const f = new PSTFile(process.argv[2]);
const out = Buffer.alloc(10);
f.readSync(out, out.length, 1048570);
process.stdout.write(out);
f.close();
''')
    (folder / 'probe.mjs').write_text('''
import { PSTFile } from 'pst-extractor';
import { createHash } from 'node:crypto';
const f = new PSTFile(process.argv[2]);
const offset = Number(process.argv[3]);
const length = Number(process.argv[4]);
const out = Buffer.alloc(length);
const n = f.readSync(out, length, offset);
console.log(JSON.stringify({bytes:n, sha256:createHash('sha256').update(out.subarray(0,n)).digest('hex')}));
f.close();
''')
    monkeypatch.setattr(bridge, '_paths', lambda: (NODE, folder/'vault_hook.cjs',
                                                    folder/'inspect.mjs', folder/'attachment.mjs'))
    source = tmp_path / 'input.pst'
    data = b'!BDN!' + b'X' * (1024 * 1024 - 10) + b'0123456789abcdef' + b'Y' * 1024
    source.write_bytes(data)
    archive = tmp_path / 'test.pstsc'
    password = 'an-example-passphrase-of-25-characters'
    encrypt_file(source, archive, password)
    return folder, archive, password, data


def test_cpp_pstfile_reads_encrypted_header_and_random_access(setup_bridge):
    folder, archive, password, data = setup_bridge
    cases = [(0, 5), (100, 1024), (1048570, 30), (len(data)-6, 6), (len(data), 10)]
    for offset, length in cases:
        script = folder / 'probe.mjs'
        proc = bridge._process(archive, password, script, str(offset), str(length))
        stdout, stderr = proc.communicate()
        assert proc.returncode == 0, (proc.returncode, stderr)
        row = json.loads(stdout)
        plain = data[offset:offset+length]
        assert row['bytes'] == len(plain)
        assert row['sha256'] == hashlib.sha256(plain).hexdigest()


def test_vault_bridge_inspect_events(setup_bridge):
    _, archive, password, _ = setup_bridge
    rows = list(bridge.iter_messages(archive, password, limit=1))
    assert rows[0]['type'] == 'message'
    assert rows[0]['subject'] == '!BDN!'
    assert rows[-1]['type'] == 'summary'
    assert rows[-1]['messages'] == 1


def test_vault_bridge_attachment_probe(setup_bridge):
    _, archive, password, data = setup_bridge
    size, digest = bridge.probe_attachment(archive, password, '41', 0)
    assert size == 10
    assert digest == hashlib.sha256(data[1048570:1048580]).hexdigest()


def test_wrong_password_rejected(setup_bridge):
    _, archive, password, _ = setup_bridge
    with pytest.raises(bridge.BridgeError):
        list(bridge.iter_messages(archive, 'a-wrong-password-of-25-characters'))


def test_tampered_second_chunk_rejected(setup_bridge):
    folder, archive, password, data = setup_bridge
    with archive.open('r+b') as f:
        f.seek(88 + 1024 * 1024 + 16 + 10)
        old = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([old[0] ^ 0x01]))
    # The first chunk still authenticates; the second no longer does.
    with EncryptedPST(archive, password) as vault:
        assert vault.read_at(0, 4) == b'!BDN'
    proc = bridge._process(archive, password, folder/'probe.mjs', str(1048580), '4')
    proc.communicate()
    assert proc.returncode != 0


def test_archive_only_is_passed_not_password_in_command_line(setup_bridge, monkeypatch):
    folder, archive, password, data = setup_bridge
    calls = []
    real_popen = subprocess.Popen
    def logged_popen(args, **kw):
        calls.append(args)
        return real_popen(args, **kw)
    monkeypatch.setattr(bridge.subprocess, 'Popen', logged_popen)
    list(bridge.iter_messages(archive, password, limit=1))
    assert calls
    assert '--require' in calls[0]
    assert password not in ' '.join(calls[0])
    assert str(archive.resolve()) in calls[0]


def test_bridge_invalid_id_rejected_without_starting_node(setup_bridge):
    _, archive, password, _ = setup_bridge
    with pytest.raises(bridge.BridgeError):
        bridge.probe_attachment(archive, password, '1;rm -rf /', 0)


def test_no_plaintext_file_created_by_bridge(setup_bridge):
    folder, archive, password, _ = setup_bridge
    list(bridge.iter_messages(archive, password, limit=1))
    assert not list(archive.parent.glob('*.pst.tmp'))
    assert not list(archive.parent.glob('*.sqlite'))
    assert not list(archive.parent.glob('*.log'))
