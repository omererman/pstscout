# Architecture decisions (initial, subject to M1/M2 tests)

## Separate responsibilities

- Portable paths: manifest references are relative to the application/vault root;
  no stored absolute drive letters; reject traversal and escaping links.
- Encrypted vault: import plain PST through an authenticated, versioned,
  random-access container that is never fully decrypted to a file.
- Parser adapter: read-only extraction of PST metadata and attachments from a
  bounded-memory random-access byte source.
- Encrypted search store: authenticated SQLCipher SQLite/FTS5 index; commit
  archive updates transactionally while keeping old valid index visible.
- UI: driverless Windows portable frontend with explicit lock/unlock lifecycle.

## Upstream PST search integration map

`KD5RYN/pst-search` (MIT; capture its original LICENSE and
THIRD_PARTY_LICENSES.md notices when code is imported):

| Upstream | Purpose / required adaptation |
|---|---|
| `pst_search/node/extract.mjs` | Messages to NDJSON via pst-extractor; use read-only synthetic PST tests |
| `pst_search/node/attachment.mjs` | Retrieve attachment from PST by node descriptor |
| `pst_search/pst.py` | Spawns Node helpers; package runtime and avoid sensitive diagnostics |
| `pst_search/db.py` | FTS5 schemas/query syntax; replace plain SQLite with authenticated encrypted DB |
| `pst_search/indexer.py` | Batch ingest; replace destructive early re-index with staging/atomic promotion |
| `pst_search/server.py` | Local search routes, but lock must disable APIs and cache/exports require review |

Upstream `pst-extractor` currently supports `PSTFile(filename)` or
`PSTFile(wholeBuffer)`. The latter must NOT be used for 8.4 GB PSTs.
Investigate a small isolated adapter replacing its synchronous read from disk
with a verified `readAt(offset, length)` interface sourced from authenticated
chunks. No real PST data enters GitHub or CI.

## Portable filesystem plan

```text
PSTScout.exe           # final packaged launcher (not yet implemented)
app/                   # packaged runtime, no user secrets
vault/                 # versioned encrypted containers (future)
    objects/<random-id>.pstsc
    search/index.db    # encrypted SQLCipher (future)
```

All application data must remain inaccessible while the vault is locked;
merely using a `.pstsc` extension is not encryption.

## M1 implementation (read-only bridge)

`src/pstscout/reader.py` launches the bundled-source `inspect.mjs` or
`attachment.mjs` using a local Node.js interpreter. The parser uses
`pst-extractor` 1.12.0. Inspect output is NDJSON, returned as typed Python
`MessageInfo`/`ScanSummary` events. Attachments stream raw bytes via a pipe
into a bounded SHA-256 probe and are not stored. Node stderr is drained but
not persisted. Metadata is printed only when the user explicitly calls the
inspection command. No PST files are imported, modified or indexed at M1.

**Important:** this bridge uses a normal filesystem PST path and does not
implement M2's encrypted random-access byte source. The JS library opens
files itself, so the M2 integration likely requires modifying the library's
`readSync` backend to call a vetted authenticated chunk reader. This is a
feasibility requirement, not a demonstrated feature.
