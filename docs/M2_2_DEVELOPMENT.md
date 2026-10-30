# PSTScout M2.2 — Experimental encrypted PST inspection

**Status: proof-of-concept, NOT production-ready or security-audited.**

This bridge permits the existing M1 `inspect.mjs` and `attachment.mjs` scripts to
read a `PSTSCV01` `.pstsc` file **without creating a temporary decrypted PST**.
The Node process authenticates the header and each requested AES-256-GCM chunk.
A 4-entry LRU caches decrypted chunks only in process memory. The original
plain-text PST stays untouched, and the experimental bridge creates no index.

## How it works

1. Python asks for a password with `getpass` and starts a local Node child.
2. The password is sent through the child's stdin pipe, never via a CLI flag,
   environment variable or process log.
3. `vault_hook.cjs` loads before M1's JavaScript reader and intercepts the
   `PSTFile.prototype.readSync()` method **only for the specified .pstsc path**.
4. `PSTFile` continues to parse a logically plaintext PST. The hook supplies
   authenticated plaintext bytes from an encrypted file on demand.
5. Python consumes the same M1 JSON-lines message events (or hashes one
   attachment stream). No complete decrypted PST is written to disk.

**Engineering caution:** Patching a third-party class prototype is a temporary
feasibility experiment, not a long-term interface. A maintained fork of
`pst-extractor` with a documented `RandomAccessByteSource` contract is the
required production direction. Encryption, key handling, cache behavior,
error handling and Windows packaging require independent security review.

## Install on your current M2.1 + M1 code tree (not a fresh M0 checkout)

Extract the M2.2 ZIP **at the PSTScout repo root**, retaining existing M1 and
M2.1 source files. M2.2 adds only the following (no overwrite of existing M1
code):

- `src/pstscout/node/vault_hook.cjs`
- `src/pstscout/vault_bridge.py`
- `tests/test_vault_bridge.py`
- `docs/M2_2_DEVELOPMENT.md`

Prerequisites: Python with installed M2.1 cryptography package; Node.js 18+
and M1's pinned `pst-extractor` installed under `src/pstscout/node/node_modules`.
No extra npm dependency is needed. Node 22 is tested locally.

### 1. Run tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Expected: your existing test count plus **8 M2.2 tests**. These 8 tests use a
simulated `PSTFile` API, not a real PST. They verify cross-runtime cryptography,
random access across chunk boundaries, original header recovery, bad password,
second-chunk tampering, attachment pipe, no plaintext file creation, and no
password exposure in Node's command-line arguments.

### 2. Encrypt an *authorized, small, real PST* as a NEW `.pstsc` file

```powershell
$sourcePst = 'D:\Test\sample.pst'
$encrypted = 'D:\Test\sample-m22.pstsc'
.\.venv\Scripts\python.exe -m pstscout.vault_cli encrypt --source $sourcePst --output $encrypted
.\.venv\Scripts\python.exe -m pstscout.vault_cli verify --archive $encrypted
```

Use your own paths and confirm storage space. Never overwrite or delete the
source PST. The `demo.bin` from M2.1 starts with `!BDN` but is NOT a valid PST;
real PST inspection with that fake file will rightly fail.

### 3. Count messages in the encrypted archive without printing mail data

```powershell
.\.venv\Scripts\python.exe -m pstscout.vault_bridge inspect --archive $encrypted --limit 0 --count-only
```

Expected: a `SUMMARY ...` line, and if applicable `SKIP_REASONS ...` and
`FOLDER_ERROR_HINTS ...`, comparable with M1's original PST scan.

### 4. Optional message preview and attachment probe

```powershell
.\.venv\Scripts\python.exe -m pstscout.vault_bridge inspect --archive $encrypted --limit 2
.\.venv\Scripts\python.exe -m pstscout.vault_bridge attachment-probe --archive $encrypted --message-id 123456 --index 0
```

Do not paste real message subjects or sender addresses into chat or GitHub.
Compare attachment hashes locally with the equivalent original M1 probe.

## Known limitations

- The source original PST remains plaintext; encrypting a copy does not erase it.
- The helper **does not** scan or verify every encrypted chunk in a partial
  inspect run; use `vault_cli verify` to authenticate all chunks first.
- The Node process may contain plaintext mail and keys in RAM. Secure zeroing
  cannot be guaranteed; host process inspection, crash dumps and swap remain
  out of scope for this prototype.
- This patch does NOT provide encrypted SQLite search, production unlock UI,
  secure manifest, malware-hardened attachment preview, or portable EXE.
- An M1 parsing error can result in skipped messages/folders; compare scan
  totals and `SKIP_REASONS` before accepting data completeness.
- The bridge is development-only, not for use on unapproved corporate devices.
