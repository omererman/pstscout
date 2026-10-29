# Security model (design, not a security certification)

## Current state

M0 performs no cryptography and stores no PSTs or indexes. Successful USB EXE,
filesystem, and Windows CNG AES-GCM smoke tests prove API availability only;
they do **not** prove the future encrypted archive is secure.

## Threat model

Primary objective: protect a lost or stolen, **locked** USB drive. This does
not protect data from malware on a computer while the vault is unlocked,
malicious administrators, system swap/hibernation/crash dumps, clipboard/history,
or user-exported plaintext attachments. Host policies and permission to store
corporate information must be respected.

## Required security design before any real-data import

1. Password-based unlock with vetted memory-hard KDF (subject to packaging and
   tested resource limits), versioned salt and parameters; no plaintext keys.
2. Authenticated encryption for metadata and fixed-size data chunks;
   nonces unique within a key domain, tag validation on every read, authenticated
   file ID, length and chunk position, versioned header, truncate/tamper checks.
3. Random-access byte reads for PST parsing with bounded RAM; never decrypt
   the entire archive to a temporary PST on the host.
4. Encrypted SQLite full-text index (e.g. SQLCipher build that includes FTS5),
   controlled journals/WAL, temp storage, safe close and key disposal.
5. No passwords, AES keys, plaintext emails, attachment text, sensitive query
   strings or raw exception messages in persistent logs. Use sanitized codes.
6. Lock/unlock lifecycle with all reads closed before lock; no browser disk
   cache or third-party remote content in message previews.
7. Tampering, wrong password, crash/restart, interrupted imports, path traversal,
   disk-full and USB-removal tests before real-data use.
8. Recovery key handling, backed-up encrypted archive and verified restore.

## Public repo safeguards

Never commit archive formats containing sensitive data, even encrypted customer
copies. Never commit real mail, source PSTs, keys, unlocked snapshots, logs,
user paths containing identifying information, or credentials.
