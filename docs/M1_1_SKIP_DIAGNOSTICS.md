# PSTScout M1.1 — Privacy-preserving skipped-record diagnostics

## Why

An M1 real-PST scan yielded `SUMMARY messages=14979 folders=18 skipped=14 limited=False`.
In M1, `skipped` is not necessarily the number of missing emails: it also counts
folder enumeration failures. The original code silently discarded the reasons.

M1.1 adds a fixed set of aggregate counters (no paths, folder names, subjects,
email addresses, body text or exception messages):

| Name | Meaning |
|---|---|
| message_read_error | PST parser threw while reading a folder child |
| empty_message | Child was empty/null |
| invalid_identifier | Child lacked a decimal descriptor identifier |
| message_processing_error | Unexpected failure while converting/emitting a message |
| folder_read_error | PST parser could not enumerate a folder's subfolders; totals may be incomplete |

## Run in an authorized development environment

```
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pstscout inspect --pst "D:\Test\sample.pst" --limit 0 --count-only
```

The same summary will now be followed by `SKIP_REASONS` when `skipped > 0`.
Inspect **only the aggregate counts**; do not share message details or the PST.

`folder_read_error > 0` is especially important: a full subtree may be missing.
Other skipped counts may be malformed or unsupported items rather than necessarily
emails. M1 will not consider real-PST completeness verified until these cases
are characterized with suitable test data.

This patch does not modify source PST files, persist message text, or introduce
logging. It does not yet make the archive encrypted or portable without Node.js.
