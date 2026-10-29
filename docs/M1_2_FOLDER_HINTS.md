# PSTScout M1.2 — Folder traversal diagnostics (aggregate only)

M1.1 found `message_read_error=0 empty_message=8 invalid_identifier=0 message_processing_error=0 folder_read_error=6` for a test PST. The six folder errors could be parser failures on leaf folders or missing real subtrees.

This patch adds **metadata hints** collected at the point where `getSubFolders()` fails, using `folder.hasSubfolders` from `pst-extractor`:

- `no_subfolders`: the PST metadata says no child folders are present (leaf hint).
- `subfolders_expected`: the PST metadata says child folders are present (potentially missing content).
- `unknown`: the metadata flag could not be read.

This is diagnostic only: metadata may be stale or corrupt, and even `no_subfolders=6` **does not prove all mail was retrieved**. We deliberately do **not** skip `getSubFolders` solely on that flag or invent missing-message counts.

Run the same PST again:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pstscout inspect --pst "D:\Test\sample.pst" --limit 0 --count-only
```

Share `SUMMARY`, `SKIP_REASONS` and `FOLDER_ERROR_HINTS` only. No folders, usernames, subjects, message bodies, exception texts or attachment contents are emitted by the command.

The test runner creates no index and writes no PST data. This diagnostic is not a substitute for independent message-count comparison with Outlook or a second independent parser. It should be performed only with authorized data.
