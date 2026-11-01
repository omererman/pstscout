"""Safely append ignored PSTScout private archive/index formats to .gitignore.

Preserves all existing content; does not modify the Git index or delete files.
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
ignore = root / '.gitignore'
existing = ignore.read_text(encoding='utf-8') if ignore.exists() else ''
patterns = [
    '*.scindex*',
    '*.pstsc',
    '*.pst',
    '*.ost',
    '*.db-journal',
    '*.sqlite-journal',
    '*.building-*',
]
lines = {line.strip() for line in existing.splitlines()}
missing = [entry for entry in patterns if entry not in lines]
if missing:
    with ignore.open('a', encoding='utf-8') as handle:
        if existing and not existing.endswith('\n'):
            handle.write('\n')
        handle.write('\n# M3.3: encrypted indices and interrupted staging files are still sensitive\n')
        for item in missing:
            handle.write(item+'\n')
print(f'M3.3 gitignore guard: {len(missing)} patterns appended')
print('Review git status and git ls-files before pushing any public commit.')
