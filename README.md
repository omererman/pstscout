# PSTScout

Portable, offline-first PST email and attachment search. No Outlook required.

**Status: M0 development foundation — NOT a secure archive, NOT ready for real PST files.**

This initial deliverable implements path handling that remains stable when a
USB drive letter changes, plus a small read/write diagnostic. It **does not**
implement encryption, PST parsing, indexing, or a portable EXE yet.

## Developer quick start (Windows PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q
python -m pstscout doctor --root "E:\"
```

Replace `E:\` with the USB root. The diagnostic writes a temporary
non-sensitive marker and removes it; it does not open any PST or store mail.

## Planned use

The final application will launch from USB without preinstalled Python,
Node.js, Outlook or Administrator rights; it will import PSTs directly into
an authenticated encrypted archive and store a protected search index.
See [development milestones](docs/ROADMAP.md) and
[security boundaries](docs/SECURITY.md).

## Repository hygiene

Do not commit PSTs, messages, attachments, indexes, encrypted archives,
recovery keys, diagnostic dumps, or real user datasets. Use synthetic fixtures.

Future reuse of `KD5RYN/pst-search` is subject to retaining its MIT license
notice and relevant third-party notices. This M0 code does not include upstream
source files.
