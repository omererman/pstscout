# M3.1 — Privacy-preserving diagnostic patch

M3 previously printed the same generic message for PST reader failures, index
validation failures, IO errors, and interruptions. This patch does **not**
change encryption, SQLite index schema, source files, or persistent storage.

It adds fixed, non-sensitive error categories and aggregate event counts:

* `PST_READER`: Node/M2 bridge failed while streaming messages. Try M2 with
  `--show-body --count-only` for the same message limit to isolate body reading.
* `INDEX_VALIDATION`: M3 rejected an event or detected an incomplete stream.
* `SQLITE`: SQLite/FTS5 failed (no raw SQL or PST values are printed).
* `TEXT_ENCODING`: SQLite or text conversion encountered unsupported Unicode.
* `FILE_IO`: numeric operating system error code only; no paths printed.
* `UNEXPECTED`: unexpected exception, redacted (no raw exception text).
* `INTERRUPTED`: scan interrupted by the user.

`messages_seen` counts events received by the indexer, not successful index
inserts. It is diagnostic only and must not be used as an integrity guarantee.

`--metadata-only` disables *body extraction* for comparison, and warns that
message bodies were not indexed. This is not a replacement for normal search.

Run on your authorized development PC, with the **same archive** that worked
with the M2.2 `vault_bridge`:

```powershell
.\.venv\Scripts\python.exe -m pstscout.search_cli --archive $encrypted --max-messages 5
.\.venv\Scripts\python.exe -m pstscout.search_cli --archive $encrypted --max-messages 200 --metadata-only
.\.venv\Scripts\python.exe -m pstscout.vault_bridge inspect --archive $encrypted --limit 200 --show-body --count-only
```

Each command requests the archive password separately. Share only the `M3 ERROR`
category, counts, and the M2 `SUMMARY`; never publish raw message previews,
passwords, paths, debug tracebacks or emails.

The index remains in-memory in M3.1. Operating system pagefile, memory dump,
and privileged process access risks remain; this is not an audited persistent
encrypted index.
