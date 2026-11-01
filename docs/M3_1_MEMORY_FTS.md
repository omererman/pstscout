# PSTScout M3.1 — In-memory full-text search prototype

The M2.2 `.pstsc` reader streams decoded message events to a Python `:memory:`
SQLite database with FTS5 enabled. This is a **development milestone**, NOT the
persistent encrypted search index required by the finished app.

### Design guardrails

- `sqlite3.connect(':memory:')` and `PRAGMA temp_store=MEMORY`: no plaintext
  SQLite `.db` file or index journal is intentionally written to any disk.
- We do not call SQLite `.backup`, `.serialize` or `VACUUM INTO`.
- `SAVEPOINT` makes each archive ingest atomic. Truncated/failed source scans
  roll back the new archive's additions.
- FTS5 query values are bound as parameters and escaped as a literal phrase.
- Reads from encrypted PST use existing `vault_bridge.iter_messages` and no
  full PST extraction. Password is entered interactively, never on argv.
- This database is **not locked/encrypted in RAM**, memory can be swapped or
  inspected by the operating system or another privileged process; do not
  claim M3.1 provides full confidentiality for corporate data.
- Terminal output shows match counts only unless `--show-results` is set.
- A full M3.1 index is recreated every launch. **Do not index 500 GB** in
  this prototype; a large FTS index can exhaust RAM. M3.2 requires real
  paged, persistent SQLCipher storage and Windows-compatible packaging.
- Body reading is capped at `--body-cap`; any truncation must be reported.
- Current `pst-extractor` helper can skip folder/message events; resulting
  scan statistics reflect those limitations, not guaranteed complete archive.

### Windows development test (authorized test data only)

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pstscout.search_cli `
  --archive "D:\Mail Arsiv 2\NOR-ROMA-ASYA-IM.m22.pstsc" `
  --max-messages 200
```

Enter archive password then one or more test search phrases; blank input exits.
`--show-results` explicitly prints private metadata to the console. Avoid
sharing those results with others.

To index the whole 14,979-message PST only if RAM is sufficient, specify
`--max-messages 0`; consider this a RAM-bound functional test, not final
persistent indexing. Body previews are capped; `body_truncated > 0` indicates
some terms may not be searchable.

### M3.2 acceptance criteria

- Use a packaged and audited SQLCipher build with FTS5 compiled in on Windows.
- No unencrypted SQLite file, WAL, journal, temp table or search cache on any
  drive. Key management and wrong-password behavior must be tested.
- Persistent, incremental per-PST indexing with resumable batches, atomic
  replacement, source-file identity tracking, safe backups and key rotation.
- Passwords and mail content never logged or passed through argv/env.
- Installation-free USB release must work under approved corporate policy.
