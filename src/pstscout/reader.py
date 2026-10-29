"""Read-only PST bridge backed by the open-source Node ``pst-extractor``.

M1 intentionally does NOT store plaintext messages, attachments, or an index.
No network access, auto-install, or per-user runtime data is performed here.
Later milestones will replace the source-file adapter with an encrypted reader.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


class PSTReaderError(RuntimeError):
    """A read-only PST helper failed. Raw stderr is not exposed."""


class AttachmentLimitExceeded(PSTReaderError):
    """Attachment was larger than the caller's in-memory/streaming policy."""


@dataclass(frozen=True)
class AttachmentInfo:
    index: int
    name: str
    size: int


@dataclass(frozen=True)
class MessageInfo:
    identifier: str
    folder_path: str
    subject: str
    sender_name: str
    sender_email: str
    recipients: tuple[str, ...]
    delivery_time: str | None
    submit_time: str | None
    body: str
    body_truncated: bool
    attachments: tuple[AttachmentInfo, ...]


@dataclass(frozen=True)
class ScanSummary:
    messages: int
    folders: int
    skipped: int
    limited: bool
    skipped_by_reason: dict[str, int] = field(default_factory=dict)
    folder_error_hints: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class AttachmentProbe:
    bytes_read: int
    sha256: str


class PSTReader:
    """Stream messages and probe attachments without writing to local disks.

    Developers must install a Node.js runtime and the pinned npm dependencies
    once while developing M1. The final portable build will bundle them.
    """

    def __init__(self, node_executable: str | Path | None = None, scripts_dir: str | Path | None = None):
        self.node_executable = str(node_executable) if node_executable else (shutil.which("node") or "")
        self.scripts_dir = Path(scripts_dir) if scripts_dir else Path(__file__).parent / "node"

    def doctor(self) -> tuple[bool, str]:
        if not self.node_executable or not Path(self.node_executable).is_file():
            # Windows PATH lookup on some installations produces a path-like string;
            # explicit paths always need to exist.
            return False, "Node.js not found. Install Node.js for M1 development."
        if not (self.scripts_dir / "node_modules" / "pst-extractor" / "package.json").is_file():
            return False, "PST helper missing. Run npm ci --ignore-scripts in src/pstscout/node."
        return True, "Node.js PST helper is ready (no PST file opened)."

    def _command(self, script: str, *args: str) -> list[str]:
        ok, detail = self.doctor()
        if not ok:
            raise PSTReaderError(detail)
        file = self.scripts_dir / script
        if not file.is_file():
            raise PSTReaderError("PST helper script missing")
        return [self.node_executable, str(file), *args]

    def events(
        self, pst_path: str | Path, *, limit: int = 20, include_body: bool = False,
        body_cap: int = 65536,
    ) -> Iterator[MessageInfo | ScanSummary]:
        """Yield metadata and summary. ``limit=0`` scans the entire PST.

        The source file is opened READ-ONLY by Node. ``include_body`` must be
        explicitly requested to avoid showing confidential text by accident.
        This bridge doesn't log, cache or persist message content.
        """
        if limit < 0 or body_cap < 1 or body_cap > 1024 * 1024:
            raise ValueError("invalid scan limit or body cap")
        pst = Path(pst_path)
        if not pst.is_file() or pst.suffix.lower() != ".pst":
            raise FileNotFoundError("PST source file not found")
        cmd = self._command(
            "inspect.mjs", str(pst.resolve()), str(limit), "1" if include_body else "0", str(body_cap)
        )
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace", bufsize=1)
        # Diagnostics may contain personal data from a third-party parser.
        # Drain stderr to prevent deadlock, but never write or display its contents.
        def drain() -> None:
            assert proc.stderr is not None
            for _ in proc.stderr:
                pass
        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        saw_summary = False
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise PSTReaderError("PST helper returned invalid JSON") from None
                if row.get("type") == "message":
                    atts = tuple(AttachmentInfo(
                        index=int(a.get("index", 0)), name=str(a.get("name", "")),
                        size=int(a.get("size", 0)),
                    ) for a in row.get("attachments", []))
                    yield MessageInfo(
                        identifier=str(row.get("identifier") or ""),
                        folder_path=str(row.get("folder_path") or ""),
                        subject=str(row.get("subject") or ""),
                        sender_name=str(row.get("sender_name") or ""),
                        sender_email=str(row.get("sender_email") or ""),
                        recipients=tuple(str(r) for r in row.get("recipients", [])),
                        delivery_time=row.get("delivery_time"),
                        submit_time=row.get("submit_time"),
                        body=str(row.get("body") or ""),
                        body_truncated=bool(row.get("body_truncated", False)),
                        attachments=atts,
                    )
                elif row.get("type") == "summary":
                    saw_summary = True
                    allowed = (
                        "message_read_error", "empty_message", "invalid_identifier",
                        "message_processing_error", "folder_read_error",
                    )
                    raw_counts = row.get("skipped_by_reason", {})
                    if not isinstance(raw_counts, dict):
                        raise PSTReaderError("PST helper returned invalid skip diagnostics")
                    counts = {name: int(raw_counts.get(name, 0)) for name in allowed}
                    if any(value < 0 for value in counts.values()) or sum(counts.values()) != int(row["skipped"]):
                        raise PSTReaderError("PST helper returned inconsistent skip diagnostics")
                    expected_hints = ("no_subfolders", "subfolders_expected", "unknown")
                    raw_hints = row.get("folder_error_hints")
                    if not isinstance(raw_hints, dict):
                        raise PSTReaderError("PST helper returned invalid folder hints")
                    hints = {name: int(raw_hints.get(name, 0)) for name in expected_hints}
                    if any(value < 0 for value in hints.values()) or sum(hints.values()) != counts["folder_read_error"]:
                        raise PSTReaderError("PST helper returned inconsistent folder hints")
                    yield ScanSummary(messages=int(row["messages"]),
                                      folders=int(row["folders"]),
                                      skipped=int(row["skipped"]),
                                      limited=bool(row.get("limited", False)),
                                      skipped_by_reason=counts,
                                      folder_error_hints=hints)
                else:
                    raise PSTReaderError("Unexpected PST protocol event")
            code = proc.wait()
            if code != 0 or not saw_summary:
                raise PSTReaderError(f"PST helper failed or returned partial output (exit={code})")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            proc.stdout.close() if proc.stdout else None
            proc.stderr.close() if proc.stderr else None
            thread.join(timeout=2)

    def attachment_probe(
        self, pst_path: str | Path, message_id: str, attachment_index: int,
        *, max_bytes: int = 64 * 1024 * 1024,
    ) -> AttachmentProbe:
        """Prove attachment retrieval by streaming its bytes into a hash.

        Never saves the plaintext attachment. Bounded memory (1 MiB chunks).
        An SHA-256 digest is a verification value, not a confidentiality measure.
        """
        pst = Path(pst_path)
        if not pst.is_file() or pst.suffix.lower() != ".pst":
            raise FileNotFoundError("PST source file not found")
        if not message_id.isdecimal() or len(message_id) > 24 or attachment_index < 0 or max_bytes < 1:
            raise ValueError("invalid attachment locator or size limit")
        cmd = self._command("attachment.mjs", str(pst.resolve()), message_id, str(attachment_index))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        sha = hashlib.sha256()
        total = 0
        try:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise AttachmentLimitExceeded("Attachment exceeds the configured probe size")
                sha.update(chunk)
            code = proc.wait()
            if code != 0:
                raise PSTReaderError(f"Attachment helper failed (exit={code})")
            return AttachmentProbe(bytes_read=total, sha256=sha.hexdigest())
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            proc.stdout.close() if proc.stdout else None
