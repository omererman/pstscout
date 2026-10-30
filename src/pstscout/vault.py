"""PSTScout M2.1: authenticated, chunked PST storage and random access.

SECURITY SCOPE: development prototype, not audited for production.  The source
PST is NEVER modified or deleted.  No plaintext PST is materialized by this
module; reads return bytes in process memory. The source plaintext continues
to exist and remains unprotected until the owner handles it separately.

Binary format PSTSCV01 is documented in docs/M2_1_FORMAT.md.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

_MAGIC = b"PSTSCV01"
_VERSION = 1
_CHUNK_DEFAULT = 1024 * 1024
_MIN_CHUNK = 64 * 1024
_MAX_CHUNK = 4 * 1024 * 1024
_MAX_READ = 8 * 1024 * 1024
_NONCE_PREFIX = 4
_SALT_LEN = 16
_TAG_LEN = 16
_HEADER_TAG_LEN = 32
# Fixed KDF profile. Changing this requires a new file-format version.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = (2**15, 8, 1)
_BASE = struct.Struct("<8sIIQIII16s4s")
_HEADER_SIZE = _BASE.size + _HEADER_TAG_LEN
_CHUNK_INFO = struct.Struct("<QI")
_MAX_PLAIN_SIZE = (1 << 63) - 1


class VaultError(Exception):
    """An encrypted archive operation failed, with no user data in the error."""


class AuthenticationError(VaultError):
    """Wrong password, damaged header, or tampered encrypted chunk."""


class InvalidArchiveError(VaultError):
    """Malformed, truncated, unsupported or oversized container."""


class SourceChangedError(VaultError):
    """Plaintext source appeared to change during encryption."""


def _check_password(password: str, *, creating: bool) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    value = password.encode("utf-8")
    if len(value) > 1024 or not value:
        raise VaultError("Password must be 1–1024 UTF-8 bytes")
    if creating and len(value) < 16:
        raise VaultError("Use a unique password at least 16 UTF-8 bytes long")
    return value


def _derive_keys(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    root = Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P).derive(password)
    separated = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=salt,
        info=b"PSTScout-M2.1-file-keys-v1",
    ).derive(root)
    return separated[:32], separated[32:]


def _valid_chunk_size(size: int) -> bool:
    return isinstance(size, int) and _MIN_CHUNK <= size <= _MAX_CHUNK and size & (size - 1) == 0


def _count_chunks(total: int, chunk: int) -> int:
    return (total + chunk - 1) // chunk


def _chunk_length(total: int, chunk: int, index: int) -> int:
    return min(chunk, total - index * chunk)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


def _aad(base_header: bytes, index: int, length: int) -> bytes:
    return base_header + _CHUNK_INFO.pack(index, length)


def _fixed_header(chunk_size: int, size: int, salt: bytes, prefix: bytes) -> bytes:
    return _BASE.pack(_MAGIC, _VERSION, chunk_size, size,
                      _SCRYPT_N, _SCRYPT_R, _SCRYPT_P, salt, prefix)


def encrypt_file(source: str | Path, dest: str | Path, password: str,
                 *, chunk_size: int = _CHUNK_DEFAULT) -> int:
    """Encrypt source to a NEW archive; never overwrite, alter or delete source.

    Output is created with exclusive-create. On Python exceptions the partial
    encrypted output is removed. After a crash, an invalid partial encrypted
    output can remain and must be deleted manually after checking its status.
    The caller must not use or distribute the output until verification passes.
    """
    if not _valid_chunk_size(chunk_size):
        raise ValueError("Unsupported chunk size")
    secret = _check_password(password, creating=True)
    src = Path(source)
    dst = Path(dest)
    if not src.is_file():
        raise FileNotFoundError("Source file not found")
    if src.resolve() == dst.resolve():
        raise VaultError("Source and destination must be different")
    # The destination must be on a user-approved filesystem. We do not create
    # parent directories, logs, temp email copies, or index files.
    with src.open("rb") as input_handle:
        stat_before = os.fstat(input_handle.fileno())
        total = stat_before.st_size
        if total < 0 or total > _MAX_PLAIN_SIZE:
            raise VaultError("Unsupported source size")
        chunks = _count_chunks(total, chunk_size)
        if chunks >= (1 << 64):
            raise VaultError("Too many chunks")
        salt = os.urandom(_SALT_LEN)
        nonce_prefix = os.urandom(_NONCE_PREFIX)
        key, mac_key = _derive_keys(secret, salt)
        header = _fixed_header(chunk_size, total, salt, nonce_prefix)
        header_tag = hmac.digest(mac_key, header, "sha256")
        cipher = AESGCM(key)
        created = False
        try:
            with dst.open("xb") as output_handle:
                created = True
                output_handle.write(header + header_tag)
                for index in range(chunks):
                    required = _chunk_length(total, chunk_size, index)
                    block = input_handle.read(required)
                    if len(block) != required:
                        raise SourceChangedError("Source size changed during encryption")
                    output_handle.write(cipher.encrypt(
                        _nonce(nonce_prefix, index), block, _aad(header, index, required)
                    ))
                if input_handle.read(1):
                    raise SourceChangedError("Source size changed during encryption")
                stat_after = os.fstat(input_handle.fileno())
                if stat_after.st_size != stat_before.st_size or stat_after.st_mtime_ns != stat_before.st_mtime_ns:
                    raise SourceChangedError("Source was modified during encryption")
                output_handle.flush()
                os.fsync(output_handle.fileno())
        except Exception:
            if created:
                try:
                    dst.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
    return chunks


class EncryptedPST:
    """Authenticated random-access reader; never exports plaintext to a file."""

    def __init__(self, archive: str | Path, password: str):
        self._file: BinaryIO | None = None
        self._aes: AESGCM | None = None
        self._base_header = b""
        self._prefix = b""
        self.size = 0
        self.chunk_size = 0
        self.chunk_count = 0
        secret = _check_password(password, creating=False)
        handle = Path(archive).open("rb")
        try:
            base = handle.read(_BASE.size)
            if len(base) != _BASE.size:
                raise InvalidArchiveError("Truncated archive header")
            magic, ver, chunk, size, n, r, p, salt, prefix = _BASE.unpack(base)
            if magic != _MAGIC or ver != _VERSION:
                raise InvalidArchiveError("Unsupported archive format")
            if not _valid_chunk_size(chunk) or size > _MAX_PLAIN_SIZE:
                raise InvalidArchiveError("Invalid chunk length or file size")
            if (n, r, p) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
                raise InvalidArchiveError("Unsupported KDF parameters")
            tag = handle.read(_HEADER_TAG_LEN)
            if len(tag) != _HEADER_TAG_LEN:
                raise InvalidArchiveError("Truncated archive header authentication")
            key, mac_key = _derive_keys(secret, salt)
            if not hmac.compare_digest(tag, hmac.digest(mac_key, base, "sha256")):
                raise AuthenticationError("Invalid password or archive authentication")
            chunk_count = _count_chunks(size, chunk)
            expected_size = _HEADER_SIZE + size + chunk_count * _TAG_LEN
            if os.fstat(handle.fileno()).st_size != expected_size:
                raise InvalidArchiveError("Archive length does not match authenticated header")
            self._file = handle
            self._aes = AESGCM(key)
            self._base_header = base
            self._prefix = prefix
            self.size = size
            self.chunk_size = chunk
            self.chunk_count = chunk_count
        except Exception:
            handle.close()
            raise

    def _read_chunk(self, index: int) -> bytes:
        if self._file is None or self._aes is None:
            raise VaultError("Archive is locked")
        if index < 0 or index >= self.chunk_count:
            raise ValueError("Chunk index is out of range")
        length = _chunk_length(self.size, self.chunk_size, index)
        offset = _HEADER_SIZE + index * (self.chunk_size + _TAG_LEN)
        self._file.seek(offset)
        ciphertext = self._file.read(length + _TAG_LEN)
        if len(ciphertext) != length + _TAG_LEN:
            raise InvalidArchiveError("Truncated encrypted chunk")
        try:
            return self._aes.decrypt(
                _nonce(self._prefix, index), ciphertext,
                _aad(self._base_header, index, length)
            )
        except InvalidTag:
            raise AuthenticationError("Encrypted data failed integrity authentication") from None

    def read_at(self, offset: int, length: int) -> bytes:
        """Read at absolute original PST byte offset; maximum 8 MiB per call."""
        if self._file is None:
            raise VaultError("Archive is locked")
        if not isinstance(offset, int) or not isinstance(length, int):
            raise TypeError("offset and length must be integers")
        if offset < 0 or length < 0 or length > _MAX_READ:
            raise ValueError("Invalid offset or read length")
        if offset >= self.size or length == 0:
            return b""
        end = min(self.size, offset + length)
        start_chunk = offset // self.chunk_size
        last_chunk = (end - 1) // self.chunk_size
        parts: list[bytes] = []
        for index in range(start_chunk, last_chunk + 1):
            plaintext = self._read_chunk(index)
            begin = max(offset - index * self.chunk_size, 0)
            stop = min(end - index * self.chunk_size, len(plaintext))
            parts.append(plaintext[begin:stop])
        return b"".join(parts)

    def verify(self) -> int:
        """Authenticate every chunk in constant *chunk-bounded* memory."""
        if self._file is None:
            raise VaultError("Archive is locked")
        for index in range(self.chunk_count):
            self._read_chunk(index)
        return self.chunk_count

    def close(self) -> None:
        """Drop references to keys and close the archive (not guaranteed RAM erasure)."""
        if self._file:
            self._file.close()
            self._file = None
        self._aes = None
        self._base_header = b""
        self._prefix = b""

    def __enter__(self) -> "EncryptedPST":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()
