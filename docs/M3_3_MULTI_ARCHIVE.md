# PSTScout M3.3 — Encrypted multi-PST collection (development preview)

## Outcome

- **Do not overwrite the proven 123.64 MB `PSTScout-M3.2-Full.scindex`.**
  Migrate it into a **new** `.scindex` file by copying its already-encrypted
  SQLCipher bytes, without rebuilding 14,979 messages or writing a plaintext DB.
- Each encrypted `.pstsc` file has an internal fingerprint and a **relative**
  path within `--root`. Windows drive-letter changes don't invalidate the
  registry; moved files can be relinked without reindexing messages.
- `scan` only inspects `.pstsc` headers and directory metadata. It reports the
  count of **new**, **present**, **moved**, **changed**, **missing**, duplicated
  and unreadable archives. No plaintext mail fields are printed.
- `add` indexes **one new encrypted PST** into the new multi-archive index.
  It skips unchanged already-indexed files. `sync` discovers new `.pstsc`
  files and prompts for each source password before indexing.
- One outer SQLCipher transaction surrounds the new archive's FTS5 rows **and**
  registry row; if parsing fails or the process is killed, previous archives
  remain searchable. M3.3 only accepts complete (`--max-messages 0`) scans.
- `search` performs a common FTS5 search across every indexed archive, with
  no PST rescan. Subject/sender detail is opt-in via `--show-results`.

## Prerequisites

Your **local M3.2 checkout** must have `src/pstscout/secure_index.py`,
`src/pstscout/persistent_cli.py`, `src/pstscout/search_index.py`,
`src/pstscout/vault_bridge.py`, M2 vault code, and `sqlcipher3==0.6.4` installed.
We are **not** using the stale GitHub `main` branch. Apply this ZIP **over**
that working M3.2 checkout. This patch only adds M3.3 files.

## Local Windows commands

```powershell
cd D:\OMERERMAN\projects\pstscout

# Review/commit outstanding M3.2 changes locally before creating a new branch.
git status --short
git switch -c feature/m3-multi-pst

# Extract PSTScout_M3_3_Coklu_Arsiv_Yamasi.zip at repo root first.
.\.venv\Scripts\python.exe scripts\m33_update_gitignore.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_collection_m33.py
```

**Real SQLCipher test is mandatory.** Unit tests with the `FakeSecureSearchIndex`
class intentionally use unencrypted SQLite in a pytest temporary directory,
not the real SQLCipher backend. The final conditional test runs on your Windows
machine after installing SQLCipher; verify it is **PASSED**, not SKIPPED.

### 1. Migrate M3.2 to M3.3 without rescanning

```powershell
$root = 'D:\Mail Arsiv 2'
$legacy = Join-Path $root 'PSTScout-M3.2-Full.scindex'
$index33 = Join-Path $root 'PSTScout-M3.3-Multi.scindex'
$encrypted = 'D:\Mail Arsiv 2\YOUR-EXACT-ENCRYPTED-ARCHIVE.pstsc'

# Confirm the file names from your working M3.2 session, do not guess.
Test-Path -LiteralPath $legacy
Test-Path -LiteralPath $encrypted
Test-Path -LiteralPath $index33   # Must be False on first migration

.\.venv\Scripts\python.exe -m pstscout.collection_cli migrate `
  --legacy-index $legacy --index $index33 --root $root --archive $encrypted
```

Expected `M3.3 MIGRATION OK: archives=1 indexed_messages=14979`.
The original index and PST are **not modified**. Migration needs about the
full existing encrypted index size as additional disk space (plus headroom).

### 2. Verify, scan, and search

```powershell
.\.venv\Scripts\python.exe -m pstscout.collection_cli verify --index $index33
.\.venv\Scripts\python.exe -m pstscout.collection_cli status --index $index33
.\.venv\Scripts\python.exe -m pstscout.collection_cli scan --index $index33 --root $root
.\.venv\Scripts\python.exe -m pstscout.collection_cli search --index $index33
```

After entering the SQLCipher index password, `search` should show
`archives=1 messages=14979` and accept `kurulum` without rescanning the PST.

### 3. Add a second DIFFERENT encrypted PST

Use a second authorized `.pst` file. Encrypt it separately with the existing
M2 `vault_cli encrypt` into a **new** `.pstsc` under `$root`. Ensure sufficient
space; never overwrite or delete a source PST.

```powershell
$newArchive = Join-Path $root 'second-test-archive.pstsc'
.\.venv\Scripts\python.exe -m pstscout.collection_cli add `
  --index $index33 --root $root --archive $newArchive --verify-source

.\.venv\Scripts\python.exe -m pstscout.collection_cli status --index $index33
.\.venv\Scripts\python.exe -m pstscout.collection_cli search --index $index33
```

`add` asks for **two passwords**: the existing SQLCipher collection password,
then the new PST container password. Both may differ. `--verify-source`
authenticates *all* chunks before indexing; this does additional disk I/O.

To discover/index *all* new `.pstsc` files in `$root`, use:

```powershell
.\.venv\Scripts\python.exe -m pstscout.collection_cli scan --index $index33 --root $root
.\.venv\Scripts\python.exe -m pstscout.collection_cli sync --index $index33 --root $root --verify-source
```

`sync` is explicitly user-triggered in M3.3; a future user interface can run
its discovery step on startup. It does not automatically process a raw `.pst`;
raw PSTs must first be imported to encrypted `.pstsc` containers.

### 4. Safety before GitHub push

```powershell
git status --short
git ls-files '*.pst' '*.pstsc' '*.scindex*' '*.db' '*.sqlite*'
git diff --cached --name-only
```

There should be **no** mail/archive/index data in the Git tree. If any is
already tracked, stop and remove it from the Git index with `git rm --cached`
for that known file, without deleting it locally. Prefer `git add` only the
M3.3 source, tests, documents and `.gitignore`.

## Current security and behavior limits

- M3.3 is not a finished security audit. The SQLCipher index is encrypted at
  rest, but sensitive search text and keys can exist in process memory and OS
  pagefile/crash data. Corporate deployment still requires explicit approval.
- **Fast fingerprint is not a full-content hash.** It uses the same M3.2
  SHA-256 of the first 128 container bytes plus file size. Interior changes
  with unchanged header and length may escape quick `scan` detection. For
  imported files use `--verify-source`; M3.4 can add periodic full verification.
- Re-encrypting the same original PST with a new salt produces a new
  `.pstsc` fingerprint, so cross-archive duplicate messages aren't detected.
- If a registered file path is replaced by a *different* archive, `scan`
  flags `changed` and `add` rejects the replacement; automatic replacement and
  safe reindexing are deferred to M3.4.
- `relative_path` is stored encrypted in the SQLCipher DB; the root path is
  supplied at runtime, not embedded. `status` prints aggregates only.
- M3.3 indexes email bodies up to the chosen cap (default 65,536 characters),
  plus attachment **names**. Twelve M3.1 bodies were truncated and 14 source
  read items skipped in earlier acceptance; retain these warnings.
- Multi-user concurrent writers, archive password rotation, backup/restore,
  filesystem rollback, USB removal recovery, and standalone Windows EXE
  packaging are separate future tests or milestones.
