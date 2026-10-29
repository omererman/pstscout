# PSTScout development gates

Each milestone is a reviewable PR with automated tests; do not merge broken
milestones or treat early development builds as secure.

| Phase | Scope | Acceptance gate |
|---|---|---|
| M0 | Python skeleton, USB relative path handling, safe diagnostics, Windows CI | Path traversal and USB root relocation tests pass |
| M1 | Read-only PST parser integration using `pst-extractor` or `pst-search` adapters | Python/Node simulated integration tests + real PST acceptance: subject, folder, dates, body, attachments and retrieval |
| M2 | Encrypted container and password-controlled unlock, random-access authenticated reads | Wrong password and tampering rejected; bounded RAM; no full plaintext PST extracted |
| M3 | Encrypted full-text index, new-file detection, failure-safe staging and index promotion | Re-open index without rebuild; add new archive only; interrupted update preserves old search |
| M4 | Native portable UI with search and controlled lock/unlock; no admin | Open/search/lock using Windows standard account, offline; sensitive content not cached on host |
| M5 | Text extraction from PDF, DOCX, XLSX and TXT attachments | Known phrases returned with original message/attachment links; unsupported formats reported |
| M6 | Packaged Windows executable, integrity, recovery, performance and security verification | Representative 8.4 GB PST, 100–500 GB aggregate scaling plan, app policy testing |

## Engineering constraints

- PSTs must remain unmodified; import into an authenticated encrypted container.
- `pst-search` uses the original PST path and unencrypted SQLite; **never run it
  on sensitive archives in an unprotected USB folder**.
- `pst-search` currently clears prior rows before replacement. New ingestion
  must use staging + atomic promotion, with explicit job state and recovery.
- PST file identity must not be just file name/path. Use portable IDs, stable
  metadata and verified content fingerprints; avoid full-file hashes on every
  normal launch (a scalable two-stage validation policy is required).
- Decrypt only the required chunks in memory and use a vetted library/API;
  the source parser accepts a filename or whole-file Buffer today, not a
  streaming virtual reader. Test the adapter before committing to M2.
- Do not add actual email corpus to CI; use synthetic fixtures only.
- First production release is blocked until M2/M3/M4/M6 security gates pass.
