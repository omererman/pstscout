# PSTScout M2.1 encrypted PST container — PSTSCV01

Status: **experimental / NOT production ready**. A driver-free encryption and random-read
proof-of-concept. Does **not** yet connect to `pst-extractor`. It does not encrypt SQLite
indexes, metadata manifests, logs, temporary files or the original source PST.

## Header (88 bytes)

Little-endian struct: `<8sIIQIII16s4s`, followed by 32-byte HMAC-SHA256:

| Field | Bytes | Meaning |
|---|---:|---|
| Magic | 8 | ASCII `PSTSCV01` |
| Version | 4 | 1 |
| Chunk size | 4 | 1 MiB default, allowed 64 KiB..4 MiB powers of two |
| Plaintext size | 8 | original size, 64-bit unsigned |
| Scrypt N, r, p | 12 | fixed at 32768, 8, 1 (resource-DoS limits enforced) |
| Salt | 16 | secure random |
| Nonce prefix | 4 | secure random |
| Header authentication | 32 | HMAC-SHA256 of 56-byte header, using a distinct HKDF key |

## Key management

- User password is UTF-8 with **no Unicode normalization**; minimum 16 bytes for new files.
- Master key: `scrypt(password, salt, N=32768, r=8, p=1, length=32)`.
- Separate 32-byte chunk key and 32-byte header HMAC key from HKDF-SHA256,
  `salt=header salt`, `info=b'PSTScout-M2.1-file-keys-v1'`, `length=64`.
- No password/derived key is stored in the container. Passwords are entered using getpass.
- Each file has a fresh salt and 4-byte nonce prefix; 64-bit big-endian unique chunk counter.

## Authenticated chunks

- AES-256-GCM, ciphertext || 16-byte tag for every chunk.
- Chunk i nonce = `nonce_prefix || uint64_be(i)` (12 bytes).
- Associated authenticated data = original 56-byte header || `uint64_le(i)` || `uint32_le(plain_chunk_length)`.
- Chunk i starts at byte `88 + i * (chunk_size + 16)`, no scanning or whole-file decrypt.
- Last chunk plaintext length = min(chunk_size, file_size - i*chunk_size).
- File size is exact: `88 + original_size + ceil(original_size/chunk_size) * 16`.
- Header HMAC and every accessed chunk tag are validated; `verify` validates ALL chunks.
- Empty files have authenticated headers even with no chunks.

## Explicit limitations / threat model

- If the locked USB is stolen, strong-password data confidentiality is the goal.
  This prototype has not undergone cryptographic/security code review.
- Creating `.pstsc` does **NOT** protect or delete the original `.pst`; avoid leaving
  a plaintext original on the USB you intend to protect.
- Host compromise after unlocking, OS swap/hibernation/crash dumps, clipboard,
  terminal/session recording, malicious software, and key memory recovery are NOT
  prevented. Python cannot promise secure erasure of immutable bytes/GC memory.
- Authenticated chunk read protects against tampering of accessed chunks; read-only
  `probe` is NOT a full-file integrity test. Run `verify` after encryption.
- A complete rollback/substitution with another valid archive is not detected;
  future signed/indexed archive manifest will be needed for stronger anti-replay.
- No persistent encrypted search index, password rotation or crash-safe resume yet.
- Interrupted encryption can leave an incomplete **encrypted** destination; that
  partial file should be removed after validating the original still exists.
- No sensitive body/log/attachment files are written by this module; destination
  file *names*, file sizes and creation times remain visible if USB isn't locked.
- Before use with confidential business data, organization approval and independent
  security review are mandatory.

## Proposed next step M2.2

The current `pst-extractor` PSTFile class reads with `fs.readSync(pstFD, buffer, 0,
length, position)` and accepts filesystem paths or **entire** Buffers. It cannot
consume `EncryptedPST.read_at` unchanged. Introduce a `RandomAccessByteSource`
interface into a maintained fork of the extractor (not global fs monkeypatch),
implement encrypted reads with a compatible Node implementation or a bounded
IPC bridge, then run real-PST message + attachment acceptance tests. Avoid
converting whole 8.4GB PST into a Buffer or writing a decoded temporary PST.
