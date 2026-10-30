"""One-time, conservative M2.1 pyproject dependency migration.

Only modifies an empty `[project]` dependency list; stops on any unexpected
layout instead of guessing, and never overwrites repository project settings.
"""
from __future__ import annotations

import pathlib
import re

path = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
if not path.exists():
    raise SystemExit("Run this script from the copied PSTScout repository root")
text = path.read_text(encoding="utf-8")
match = re.search(r"(?ms)^\[project\]\s*\n(.*?)(?=^\[|\Z)", text)
if not match:
    raise SystemExit("Cannot find [project] section; no changes made")
section = match.group(1)
if re.search(r"(?m)^dependencies\s*=\s*\[\s*\]", section):
    new_section = re.sub(
        r"(?m)^dependencies\s*=\s*\[\s*\]",
        'dependencies = ["cryptography>=44,<47"]', section, count=1
    )
    text = text[:match.start(1)] + new_section + text[match.end(1):]
    path.write_text(text, encoding="utf-8")
    print("Updated pyproject.toml project dependencies for M2.1")
elif "cryptography" in section:
    print("M2 dependency already present; no change")
else:
    raise SystemExit("Nonempty project dependencies: add cryptography>=44,<47 manually")
