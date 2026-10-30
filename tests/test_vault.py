"""M2.1 synthetic byte tests: NO real user data, NO external services."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from pstscout.vault import (
    EncryptedPST, AuthenticationError, InvalidArchiveError, VaultError,
    encrypt_file,
)

PASSWORD = "Example!Very-Long-Phrase-2026"
CHUNK = 64 * 1024


@pytest.fixture()
def synthetic(tmp_path: Path):
    # Looks like a valid PST signature but is NOT an Outlook PST; only bytes.
    raw = b"!BDN" + os.urandom(2 * CHUNK + 741)
    source = tmp_path / "synthetic.pst"
    source.write_bytes(raw)
    target = tmp_path / "hidden.pstsc"
    yield source, target, raw


def _create(synthetic, chunk_size: int = CHUNK):
    src, dest, data = synthetic
    count = encrypt_file(src, dest, PASSWORD, chunk_size=chunk_size)
    return src, dest, data, count


def test_roundtrip_random_access(synthetic):
    _, dest, data, count = _create(synthetic)
    assert count == 3
    with EncryptedPST(dest, PASSWORD) as archive:
        assert archive.size == len(data)
        assert archive.chunk_count == 3
        assert archive.read_at(0, 4) == b"!BDN"
        assert archive.read_at(0, 513) == data[:513]
        assert archive.read_at(CHUNK - 10, 100) == data[CHUNK-10:CHUNK+90]
        assert archive.read_at(CHUNK * 2 - 1, CHUNK) == data[CHUNK*2-1:CHUNK*3-1]
        assert archive.read_at(len(data) - 2, 100) == data[-2:]
        assert archive.read_at(len(data), 10) == b""
        assert archive.read_at(10, 0) == b""
        assert archive.verify() == 3


def test_original_remains_unmodified(synthetic):
    source, _, data, _ = _create(synthetic)
    assert source.read_bytes() == data


def test_ciphertext_does_not_contain_pst_header_or_plaintext(synthetic):
    _, target, data, _ = _create(synthetic)
    encrypted = target.read_bytes()
    assert not encrypted.startswith(b"!BDN")
    assert encrypted[88:124] != data[:36]
    assert len(encrypted) == 88 + len(data) + 3 * 16


def test_wrong_password_fails(synthetic):
    _, target, _, _ = _create(synthetic)
    with pytest.raises(AuthenticationError):
        EncryptedPST(target, "Incorrect!LongPassword")


def test_password_minimum_and_maximum(synthetic):
    source, target, _ = synthetic
    with pytest.raises(VaultError):
        encrypt_file(source, target, "short")
    with pytest.raises(VaultError):
        encrypt_file(source, target, "x" * 1025)
    assert not target.exists()


def test_no_overwrite(synthetic):
    source, target, _, _ = _create(synthetic)
    before = target.read_bytes()
    with pytest.raises(FileExistsError):
        encrypt_file(source, target, PASSWORD)
    assert target.read_bytes() == before


def test_source_destination_must_differ(synthetic):
    source, _, data = synthetic
    with pytest.raises(VaultError):
        encrypt_file(source, source, PASSWORD)
    assert source.read_bytes() == data


def test_ciphertext_tampering_detected(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open("r+b") as f:
        f.seek(88 + 10)
        old = f.read(1)
        f.seek(88 + 10)
        f.write(bytes([old[0] ^ 0x55]))
    with EncryptedPST(target, PASSWORD) as archive:
        with pytest.raises(AuthenticationError):
            archive.read_at(0, 16)
        with pytest.raises(AuthenticationError):
            archive.verify()


def test_middle_chunk_corruption_detected_by_full_verify(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open("r+b") as f:
        f.seek(88 + CHUNK + 16 + 5)
        current = f.read(1)
        f.seek(88 + CHUNK + 16 + 5)
        f.write(bytes([current[0] ^ 0xFF]))
    with EncryptedPST(target, PASSWORD) as archive:
        assert archive.read_at(0, 32) == b"!BDN" + archive.read_at(4, 28)
        with pytest.raises(AuthenticationError):
            archive.read_at(CHUNK + 2, 4)
        with pytest.raises(AuthenticationError):
            archive.verify()


def test_modified_authenticated_header_rejected(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open("r+b") as f:
        f.seek(54)
        current = f.read(1)
        f.seek(54)
        f.write(bytes([current[0] ^ 0x10]))
    with pytest.raises(AuthenticationError):
        EncryptedPST(target, PASSWORD)


def test_truncated_archive_rejected(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open("r+b") as f:
        f.truncate(target.stat().st_size - 1)
    with pytest.raises(InvalidArchiveError):
        EncryptedPST(target, PASSWORD)


def test_trailing_bytes_rejected(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open("ab") as f:
        f.write(b"BAD")
    with pytest.raises(InvalidArchiveError):
        EncryptedPST(target, PASSWORD)


def test_unsupported_magic_rejected(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open("r+b") as f:
        f.write(b"NOTAVALT")
    with pytest.raises(InvalidArchiveError):
        EncryptedPST(target, PASSWORD)


def test_read_safety_checks(synthetic):
    _, target, _, _ = _create(synthetic)
    with EncryptedPST(target, PASSWORD) as archive:
        for off, length in [(-1, 2), (0, -1), (0, 10*1024*1024)]:
            with pytest.raises(ValueError):
                archive.read_at(off, length)
        with pytest.raises(TypeError):
            archive.read_at(0.1, 2)
    with pytest.raises(VaultError):
        archive.read_at(0, 2)


def test_empty_archive_authenticated(tmp_path):
    source = tmp_path / 'empty.pst'
    target = tmp_path / 'empty.pstsc'
    source.write_bytes(b"")
    assert encrypt_file(source, target, PASSWORD) == 0
    assert target.stat().st_size == 88
    with EncryptedPST(target, PASSWORD) as archive:
        assert archive.read_at(0, 100) == b""
        assert archive.verify() == 0
    with target.open('r+b') as f:
        f.seek(87)
        val = f.read(1)
        f.seek(87)
        f.write(bytes([val[0] ^ 1]))
    with pytest.raises(AuthenticationError):
        EncryptedPST(target, PASSWORD)


def test_same_password_different_ciphertexts(synthetic):
    source, target, _, _ = _create(synthetic)
    target2 = target.parent / 'second.pstsc'
    encrypt_file(source, target2, PASSWORD, chunk_size=CHUNK)
    assert target.read_bytes() != target2.read_bytes()


def test_invalid_chunk_size(synthetic):
    source, target, _ = synthetic
    with pytest.raises(ValueError):
        encrypt_file(source, target, PASSWORD, chunk_size=1024)
    assert not target.exists()


def test_cli_roundtrip_no_password_echo(tmp_path, monkeypatch, capsys):
    from pstscout import vault_cli
    src = tmp_path / 'demo.pst'; dst = tmp_path / 'demo.pstsc'
    src.write_bytes(b'!BDN' + b'example-data')
    values = iter([PASSWORD, PASSWORD, PASSWORD, PASSWORD])
    monkeypatch.setattr(vault_cli.getpass, 'getpass', lambda _: next(values))
    assert vault_cli.main(['encrypt', '--source', str(src), '--output', str(dst)]) == 0
    assert vault_cli.main(['verify', '--archive', str(dst)]) == 0
    assert vault_cli.main(['probe', '--archive', str(dst), '--offset', '0', '--length', '4']) == 0
    out = capsys.readouterr().out
    assert 'Full archive verification OK' in out
    assert hashlib.sha256(b'!BDN').hexdigest() in out
    assert PASSWORD not in out
    assert str(src) not in out


def test_header_bad_chunk_params_rejected(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open('r+b') as f:
        f.seek(12)
        f.write(b'\x00\x00\x00\x00')
    with pytest.raises(InvalidArchiveError):
        EncryptedPST(target, PASSWORD)


def test_archive_portable_to_another_location(synthetic, tmp_path):
    _, target, data, _ = _create(synthetic)
    moved = tmp_path / 'new-drive-folder'
    moved.mkdir()
    new_location = moved / 'archive-no-name.pstsc'
    target.rename(new_location)
    with EncryptedPST(new_location, PASSWORD) as archive:
        assert archive.read_at(CHUNK-5, 13) == data[CHUNK-5:CHUNK+8]


def test_random_offsets_bounded_reads(synthetic):
    import random
    _, target, data, _ = _create(synthetic)
    rng = random.Random(67)
    with EncryptedPST(target, PASSWORD) as archive:
        for _ in range(150):
            offset = rng.randrange(0, len(data) + CHUNK)
            length = rng.randrange(0, 2 * CHUNK + 10)
            assert archive.read_at(offset, length) == data[offset:offset+length]


def test_last_chunk_tamper_detected_in_full_verification(synthetic):
    _, target, _, _ = _create(synthetic)
    with target.open('r+b') as f:
        f.seek(-1, 2)
        last = f.read(1)
        f.seek(-1, 2)
        f.write(bytes([last[0] ^ 1]))
    with EncryptedPST(target, PASSWORD) as archive:
        assert archive.read_at(0, 4) == b'!BDN'
        with pytest.raises(AuthenticationError):
            archive.verify()


def test_cli_reports_short_password_without_exposing_password(tmp_path, monkeypatch, capsys):
    from pstscout import vault_cli
    source = tmp_path / "source.bin"
    dest = tmp_path / "archive.pstsc"
    source.write_bytes(b"!BDN" + b"X" * 1024)
    weak = "short-secret"
    monkeypatch.setattr(vault_cli.getpass, "getpass", lambda prompt: weak)
    assert vault_cli.main(["encrypt", "--source", str(source), "--output", str(dest)]) == 1
    output = capsys.readouterr().out
    assert "Password too short" in output
    assert "16 UTF-8 bytes" in output
    assert weak not in output
    assert str(source) not in output
    assert not dest.exists()


def test_cli_reports_existing_output_safely(tmp_path, monkeypatch, capsys):
    from pstscout import vault_cli
    source = tmp_path / "source.bin"
    dest = tmp_path / "archive.pstsc"
    source.write_bytes(b"!BDN" + b"Y" * 1024)
    dest.write_bytes(b"existing")
    monkeypatch.setattr(vault_cli.getpass, "getpass", lambda prompt: PASSWORD)
    assert vault_cli.main(["encrypt", "--source", str(source), "--output", str(dest)]) == 1
    output = capsys.readouterr().out
    assert "output already exists" in output
    assert str(dest) not in output
    assert dest.read_bytes() == b"existing"


def test_cli_unknown_vault_exception_has_no_raw_message(capsys):
    from pstscout import vault_cli
    # Internal errors containing untrusted content must never echo that content.
    vault_cli._print_safe_error(VaultError("Sensitive e-mail subject: PRIVATE"))
    output = capsys.readouterr().out
    assert "operation rejected" in output
    assert "PRIVATE" not in output
