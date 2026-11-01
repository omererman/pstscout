# PSTScout M3.2 — SQLCipher persistent full-text index (preview)

## Goal and scope

- Keep M3.1 intact (`python -m pstscout.search_cli` remains the RAM-only demo).
- `persistent_cli build` reads the M2.2 encrypted PST stream and writes an **encrypted SQLCipher 4 database** from its first page. No temporary plaintext SQLite database is created.
- Index data contains searchable email metadata, body prefixes (default 65,536 characters per message), and attachment *names* (not attachment contents).
- `persistent_cli search` opens that encrypted index directly; no PST read on later sessions.
- Initial development requires Node.js and the M2 reader. Future standalone EXE packaging is not yet implemented.

## Install (Windows, developer environment)

Run from `D:\OMERERMAN\projects\pstscout`:

```powershell
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: sqlcipher3==0.6.4
.\.venv\Scripts\python.exe -m pytest -q
```

`sqlcipher3` 0.6.4 has published CPython 3.14 Windows x64 binary wheels as of 2026-10-31, according to PyPI. The package must expose `PRAGMA cipher_version` beginning with `4.` and support FTS5. The code **refuses to fall back** to plain `sqlite3` for persistent storage. If package installation is blocked by organizational controls, request approval; do not install from unknown mirrors.

## Tests with synthetic data

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_secure_index_m32.py
```

The synthetic test suite includes several tests using a mocked backend that is **not encrypted**. The final integration test, `test_real_sqlcipher_encrypted_at_rest`, uses the actual `sqlcipher3` package. It checks that standard SQLite cannot read the file, the encrypted bytes exclude known plaintext, wrong passwords fail, and reopen + FTS search work. **Do not accept M3.2 without that final test passing.**

## Real data smoke test (authorized local D: storage only)

The existing M2.2 archive is on D:. Keep index files outside the Git repository.

```powershell
$encrypted = 'D:\Mail Arsiv 2\YOUR-ARCHIVE.pstsc'  # Use your exact existing .pstsc path
$index = 'D:\Mail Arsiv 2\PSTScout-M3.2.scindex'

.\.venv\Scripts\python.exe -m pstscout.persistent_cli build `
  --archive $encrypted --index $index --max-messages 200

.\.venv\Scripts\python.exe -m pstscout.persistent_cli verify --index $index
.\.venv\Scripts\python.exe -m pstscout.persistent_cli search --index $index
```

At first, use 200 records to ensure the right environment. For the complete 14,979 message validation, choose a **different index filename** (not overwrite) and run with `--max-messages 0`. Expected scan metadata from the user's earlier M3.1 run: messages 14,979, folders 18, skipped 14, body_truncated 12.

`build` uses one password for both the `.pstsc` archive and new index, but derives keys independently through each format's own KDF and salt. No password appears in the command line or source files. `search` and `verify` need only the index password; no archive path is passed.

The index is created under a randomly named **encrypted staging file in the same directory**, verified, then renamed to its final path. Existing indexes are not intentionally overwritten. If a forced shutdown interrupts the run, a leftover `*.building-*` file may remain; it too should be encrypted, but inspect before deleting. No plaintext PST should be exported or committed.

## Limits and risks

- M3.2 is a development preview, **not a completed security audit or corporate deployment approval**.
- `SQLCipher` does not guarantee private content cannot appear in OS paging, memory dumps, malware/EDR captures or crash telemetry. The M2 reader streams decrypted text through in-memory pipes.
- `PRAGMA temp_store=MEMORY`, journal mode `DELETE`, `cipher_memory_security=ON`, and full synchronous writes are configured. SQLCipher encrypts database/journal pages. Unclean shutdown may leave an encrypted journal.
- Search indexes only the first 65,536 body characters per message by default; prior run reported 12 truncated bodies. 14 skipped entries also persist as provenance warnings, not proof of complete coverage.
- Full-file fingerprints and automated changed-archive detection will be designed in M3.3. The M3.2 fingerprint only identifies the initial container header and length.
- Interrupted incremental updates, backup/version rotation, concurrent writers, integrity against hostile source modification, FTS tokenization edge cases and key rotation are NOT yet solved.
- `.scindex`, `.pstsc`, `.pst`, `*.building-*` and any mail-derived logs or test data should be excluded from Git.

## Source references

- SQLCipher API: https://www.zetetic.net/sqlcipher/sqlcipher-api/
- Python wheels: https://pypi.org/project/sqlcipher3/
