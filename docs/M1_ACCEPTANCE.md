# M1 — read-only PST acceptance test

**Goal:** verify an unmodified Outlook PST can be browsed without Outlook,
including message headers, dates, bodies, attachments and random attachment
retrieval. This is a DEVELOPMENT test, not the final safe encrypted archive.

## Automated checks

- M0's 20 checks remain passing.
- M1's synthetic tests verify Python-to-Node JSON line protocol, UTF-8 metadata,
  missing PST, invalid input, bounded attachment probes, text preview opt-in,
  count-only CLI, and no persisted email/index data.
- Fake JS module used in CI is NOT a real Outlook PST parser.

## Human acceptance on an authorized test PST

1. `python -m pstscout pst-doctor` reports helper ready.
2. `python -m pstscout inspect --pst "<path>" --limit 5` returns subjects,
   sender, date, folder and attachment names without errors.
3. On a **test** message, `--show-body --limit 2` shows expected body.
4. `--limit 0 --count-only` reports totals (this can take a while for 8.4 GB).
5. Check `skipped` (prefer zero; otherwise investigate missing data).
6. For a known attachment, use `attachment-probe --message-id <id> --index 0`
   and verify expected byte count/hash using a known synthetic attachment.
7. Repeat with PST on removable USB and with a changed USB drive letter.
8. No `.db`, `.log`, mail message or extracted attachment files appear as a
   result of `inspect` and `attachment-probe`.

**Definition of done:** passes the above with an authorized real Outlook PST.
Passing unit tests alone does NOT complete real-PST acceptance.

**Handling:** run only on an allowed computer; never paste mail subjects,
addresses or contents into GitHub or a chat. The PST remains unencrypted until
M2, so do not copy sensitive mail to an unprotected removable disk.
