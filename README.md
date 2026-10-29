# PSTScout

Portable, offline-first PST email and attachment search. No Outlook required.

**Development milestone: M1 PST reading prototype (`0.2.0.dev0`). NOT an encrypted
archive, NOT a search index, NOT a portable Windows EXE yet.** Do not copy
confidential or corporate mail to an unprotected USB just to run this test.

### What's working

- M0: USB-independent relative paths, path traversal prevention, removable drive diagnostics.
- M1: Read-only extraction of mail metadata (subject, sender, recipients, dates,
  folder, attachment listing) using `pst-extractor` via a local Node.js helper.
- Optional explicit body previews (default OFF), with truncation markers.
- Selected attachment streaming probe, with SHA-256 and total size; **never
  writes the attachment to disk**.
- All subprocess diagnostics are discarded; no file logs, search DB, imported
  files or temp email copies are created by M1.

### M1 developer setup — Windows PowerShell, on an authorized development PC

M1 still requires **Python 3.10+**, **Node.js 18+**, and an initial internet
connection to install npm packages. Outlook is NOT required. The final packaged
release will bundle runtimes and operate offline without installing anything
on the company PC; that is a later milestone.

```powershell
# From the PSTScout repository root:
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

# Installs pinned PST parser and related deps, once, into node_modules:
Push-Location src\pstscout\node
npm ci --ignore-scripts --no-audit --no-fund
Pop-Location

.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pstscout pst-doctor
```

**Read-only small preview** (replace the path with a PST already approved for
local testing; source is not modified):

```powershell
.\.venv\Scripts\python.exe -m pstscout inspect --pst "D:\Test\sample.pst" --limit 5
```

To explicitly inspect message bodies for debugging on your authorized PC:

```powershell
.\.venv\Scripts\python.exe -m pstscout inspect --pst "D:\Test\sample.pst" --limit 2 --show-body
```

To count all messages **without printing personal mail** (can take time):

```powershell
.\.venv\Scripts\python.exe -m pstscout inspect --pst "D:\Test\sample.pst" --limit 0 --count-only
```

To verify one attachment without storing the plaintext bytes, take the
`ID:` and the attachment `index` from the preview:

```powershell
.\.venv\Scripts\python.exe -m pstscout attachment-probe --pst "D:\Test\sample.pst" --message-id "123456" --index 0
```

By default this probes up to 64 MiB and reports byte count and hash; adjust
`--max-mib` for deliberately larger attachments. **Do not paste real message
subjects, addresses, hashes or other private metadata into a public GitHub
issue**; share the final `SUMMARY` counts and sanitized failure codes instead.

### Limits / decisions for M2

1. **No security claims yet.** M1 opens source PST directly and has no
   encryption/unlock behavior. Use a permitted *test* PST on your own computer.
2. `pst-extractor` opens a filesystem path or full in-memory buffer; random
   access over authenticated encrypted blocks is not implemented.
3. An invalid message may be skipped; `skipped` count must be checked. M1
   will not be considered data-complete until real-PST acceptance passes.
4. Body preview and metadata are streamed through pipes, not saved. Printing
   them in a terminal can expose private content through screen/session capture.
5. The parser's external JS dependency has to be installed in development.
   A driver-free single-file/portable Windows build is part of M6.
6. M1 tests simulate `pst-extractor` with a fake local npm module; they do
   **not** demonstrate compatibility with real Outlook PST files.

See [M1 acceptance criteria](docs/M1_ACCEPTANCE.md), [roadmap](docs/ROADMAP.md)
and [security rules](docs/SECURITY.md).
