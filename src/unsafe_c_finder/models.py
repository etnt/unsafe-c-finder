from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Decision = Literal["pass", "warn", "fail"]


@dataclass(frozen=True, slots=True)
class Snippet:
    identifier: str
    path: str
    language: str
    after: str
    before: str = ""
    context: str = ""
    hunk_header: str = ""
    change_kind: str = "snippet"

    def state(self) -> dict[str, str]:
        return {
            "language": self.language,
            "path": self.path,
            "change_kind": self.change_kind,
            "hunk_header": self.hunk_header,
            "before": self.before,
            "after": self.after,
            "context": self.context,
        }


@dataclass(frozen=True, slots=True)
class RequestMetadata:
    model: str
    latency_ms: float
    attempts: int
    input_tokens: int | None = None


@dataclass(slots=True)
class Classification:
    snippet: Snippet
    unsafe_probability: float
    decision: Decision
    cwe: str | None = None
    cwe_probability: float | None = None
    cwe_probabilities: dict[str, float] | None = None
    stage1: RequestMetadata | None = None
    stage2: RequestMetadata | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snippet": {
                "identifier": self.snippet.identifier,
                "path": self.snippet.path,
                "language": self.snippet.language,
                "change_kind": self.snippet.change_kind,
                "hunk_header": self.snippet.hunk_header,
            },
            "unsafe_probability": self.unsafe_probability,
            "decision": self.decision,
            "cwe": self.cwe,
            "cwe_probability": self.cwe_probability,
            "cwe_probabilities": self.cwe_probabilities,
            "stage1": asdict(self.stage1) if self.stage1 else None,
            "stage2": asdict(self.stage2) if self.stage2 else None,
            "errors": self.errors,
        }
