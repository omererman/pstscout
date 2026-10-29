PSTScout M1.2 patch — APPLY ON TOP OF M1.1

Copy the contents of this ZIP into the root of your existing pstscout git checkout, overwriting the 4 modified files. The patch DOES NOT contain a complete repository.

Run: .\.venv\Scripts\python.exe -m pytest -q
Then rerun the same PST: .\.venv\Scripts\python.exe -m pstscout inspect --pst "PATH\FILE.pst" --limit 0 --count-only

Only share SUMMARY, SKIP_REASONS, FOLDER_ERROR_HINTS. NEVER upload PST files, stdout of message-by-message inspection, passwords, or any raw parser errors.
