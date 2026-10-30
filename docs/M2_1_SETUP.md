# M2.1 setup and acceptance

Start from your existing `pstscout` checkout with M1 and M1.2 already installed.
Do NOT replace your M1 `cli.py`, `reader.py`, Node tools or tests.

1. Create a **new branch** from your working M1 branch:
   `git switch -c feature/m2-encrypted-storage`.
2. Extract the M2 ZIP at the root of the checkout, retaining folder paths.
3. `python scripts/m2_update_project.py` (adds Python `cryptography` dependency).
4. `.\.venv\Scripts\python.exe -m pip install -e ".[dev]"`.
5. `.\.venv\Scripts\python.exe -m pytest -q`.

19 additional M2-specific synthetic tests should pass on top of your existing M1 tests.
Keep secrets, real archives, index files, `.pstsc`, `.pst` and exported data out of Git.

## Optional local demonstration on non-confidential source

```powershell
# Demo ONLY: test bytes, not a real Outlook PST; outside the Git repo.
$demo = Join-Path $env:TEMP "PSTScout-M2-Test"
New-Item -ItemType Directory -Force $demo | Out-Null
.\.venv\Scripts\python.exe -c "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b'!BDN' + b'X' * 1500000)" "$demo\demo.bin"
.\.venv\Scripts\python.exe -m pstscout.vault_cli encrypt --source "$demo\demo.bin" --output "$demo\demo.pstsc"
.\.venv\Scripts\python.exe -m pstscout.vault_cli verify --archive "$demo\demo.pstsc"
.\.venv\Scripts\python.exe -m pstscout.vault_cli probe --archive "$demo\demo.pstsc" --offset 0 --length 4
```

The `probe` of offset 0 length 4 should hash the ASCII `!BDN` bytes. Password is
entered at the console twice when encrypting and once for subsequent commands.
Don't put passwords directly in scripts or command-line arguments. The CLI
prints the SHA-256 of explicitly probed bytes; never share this output with
sensitive inputs. Delete demo files after tests.

## Acceptance boundaries

- New `.pstsc` file is created without altering the source PST.
- Wrong passwords and bit-flipped encrypted chunks are rejected.
- `EncryptedPST.read_at(offset, length)` returns only the requested region, not
  the whole original PST. `verify()` reads and authenticates every chunk.
- The final archive is **not yet an Outlook-readable PST** (the `pst-extractor`
  module does not know how to read `.pstsc` yet). M2.2 must integrate the reader.
- The final portable EXE and complete USB locking UI are still separate phases.
- A locked archive protects only ciphertext; an unencrypted source copy in the
  same USB renders this protection meaningless. Do not migrate personal or
  corporate archives to this experimental prototype.
