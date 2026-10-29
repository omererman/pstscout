"""Portable-drive paths and safe filesystem diagnostics.

Nothing in this module reads PST contents or creates an archive/index.
All stored paths are relative to the vault root so USB drive-letter changes
never invalidate an archive reference.
"""

from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath


class UnsafeVaultPath(ValueError):
    """A stored relative path is unsafe or outside its vault."""


def application_root(executable: str | Path | None = None) -> Path:
    """Return the directory holding an executable or bundled launcher.

    During development, pass an explicit executable path. When packaged as
    a portable EXE, ``sys.executable`` is that EXE's location.
    """
    return Path(executable if executable is not None else sys.executable).resolve().parent


def normalize_relative_path(stored_path: str) -> str:
    """Validate a manifest path and return a portable forward-slash version.

    Reject absolute/drive/UNC paths, parent traversal, empty components and
    Windows alternate data-stream separators. This is not a sanitizer for
    user-controlled filenames; use generated IDs for encrypted containers.
    """
    if not isinstance(stored_path, str):
        raise TypeError("stored_path must be a string")
    if not stored_path or "\x00" in stored_path:
        raise UnsafeVaultPath("empty or invalid stored path")
    win = PureWindowsPath(stored_path)
    normalized = stored_path.replace("\\", "/")
    if win.drive or win.root or normalized.startswith("/"):
        raise UnsafeVaultPath("absolute or drive-based path is not allowed")
    parts = normalized.split("/")
    if any(part in ("", ".", "..") or ":" in part for part in parts):
        raise UnsafeVaultPath("invalid path component")
    return "/".join(parts)


def resolve_vault_path(vault_root: str | Path, stored_path: str) -> Path:
    """Resolve and confine a stored relative path to the vault.

    Resolving the candidate detects existing symlinks/junctions that would
    escape the vault; no files are created by this operation.
    """
    normalized = normalize_relative_path(stored_path)
    root = Path(vault_root).resolve()
    target = root.joinpath(*normalized.split("/")).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise UnsafeVaultPath("path escapes vault") from exc
    return target


def store_vault_path(vault_root: str | Path, target: str | Path) -> str:
    """Turn a path inside the vault into a portable manifest reference."""
    root = Path(vault_root).resolve()
    target_path = Path(target).resolve()
    try:
        relative = target_path.relative_to(root)
    except ValueError as exc:
        raise UnsafeVaultPath("path escapes vault") from exc
    return normalize_relative_path(relative.as_posix())


@dataclass(frozen=True)
class ProbeResult:
    readable: bool
    writable: bool


def check_volume_access(usb_root: str | Path) -> ProbeResult:
    """Check basic USB access using a short non-sensitive temporary marker.

    The probe writes no password, email or archive content. Temporary marker
    is unlinked on normal completion, including read failures.
    """
    root = Path(usb_root)
    if not root.is_dir():
        return ProbeResult(readable=False, writable=False)
    try:
        with tempfile.NamedTemporaryFile(
            mode="w+b", dir=root, prefix=".pstscout-probe-", delete=True
        ) as stream:
            stream.write(b"PSTSCOUT_TEST")
            stream.flush()
            stream.seek(0)
            return ProbeResult(readable=stream.read() == b"PSTSCOUT_TEST", writable=True)
    except (OSError, PermissionError):
        return ProbeResult(readable=True, writable=False)
