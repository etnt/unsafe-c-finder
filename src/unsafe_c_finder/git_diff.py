from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import Snippet

C_EXTENSIONS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


class GitDiffError(RuntimeError):
    pass


def staged_diff(context_lines: int = 5, *, cwd: Path | None = None) -> str:
    command = [
        "git",
        "-c",
        "core.quotePath=false",
        "diff",
        "--cached",
        f"--unified={context_lines}",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "--no-prefix",
        "--",
    ]
    completed = subprocess.run(
        command, text=True, capture_output=True, check=False, cwd=cwd
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or "git diff failed"
        raise GitDiffError(detail)
    return completed.stdout


def parse_unified_diff(diff: str) -> list[Snippet]:
    snippets: list[Snippet] = []
    path: str | None = None
    hunk_header = ""
    before: list[str] = []
    after: list[str] = []
    context: list[str] = []
    hunk_number = 0

    def flush() -> None:
        nonlocal before, after, context, hunk_header, hunk_number
        if (
            path
            and Path(path).suffix.lower() in C_EXTENSIONS
            and hunk_header
            and after
        ):
            hunk_number += 1
            snippets.append(
                Snippet(
                    identifier=f"{path}:{hunk_number}",
                    path=path,
                    language=_language(path),
                    before="\n".join(before),
                    after="\n".join(after),
                    context="\n".join(context),
                    hunk_header=hunk_header,
                    change_kind="hunk",
                )
            )
        before = []
        after = []
        context = []
        hunk_header = ""

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            flush()
            path = None
            hunk_number = 0
        elif line.startswith("+++ "):
            candidate = line[4:]
            path = None if candidate == "/dev/null" else candidate
        elif HUNK_RE.match(line):
            flush()
            hunk_header = line
        elif hunk_header:
            if line.startswith("+") and not line.startswith("+++"):
                after.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                before.append(line[1:])
            elif line.startswith(" "):
                context.append(line[1:])
            elif line == r"\ No newline at end of file":
                continue
    flush()
    return snippets


def snippets_from_paths(paths: list[str]) -> list[Snippet]:
    snippets: list[Snippet] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.suffix.lower() not in C_EXTENSIONS:
            continue
        try:
            code = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise GitDiffError(f"cannot read {path}: {exc}") from exc
        snippets.append(
            Snippet(
                identifier=str(path),
                path=str(path),
                language=_language(str(path)),
                after=code,
                change_kind="file",
            )
        )
    return snippets


def _language(path: str) -> str:
    extension = Path(path).suffix.lower()
    if extension == ".c":
        return "c"
    if extension == ".h":
        return "c/c++"
    return "c++"
