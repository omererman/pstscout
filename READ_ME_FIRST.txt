PSTScout M3.3 — multi-archive encrypted index (additive patch)

This package DOES NOT replace your M3.2 modules or modify your existing
PSTScout-M3.2-Full.scindex. Apply it to your already-working local M3.2 checkout.

1. Extract ZIP in D:\OMERERMAN\projects\pstscout, retaining folders.
2. .\.venv\Scripts\python.exe scripts\m33_update_gitignore.py
3. .\.venv\Scripts\python.exe -m pytest -q tests\test_collection_m33.py
4. Read docs\M3_3_MULTI_ARCHIVE.md and run the migrate/verify/search commands.
5. Then test a SECOND, different encrypted PST with add or sync.

MANDATORY: the real SQLCipher test must run (not skip) on your Windows machine.
M3.3 fake-backend tests are for control flow only, not proof of encryption.
Passwords are prompted; never paste into terminal arguments, GitHub or chat.
Only source code and test fixtures belong in Git, NEVER .pst, .pstsc, .scindex,
SQLite DBs, keys or real e-mail contents.

This is a development preview requiring security review before corporate use.
