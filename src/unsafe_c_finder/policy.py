from __future__ import annotations

from dataclasses import dataclass

from .models import Decision


@dataclass(frozen=True, slots=True)
class Policy:
    followup_threshold: float = 0.60
    fail_threshold: float = 0.85
    strict: bool = False

    def __post_init__(self) -> None:
        for name, value in (
            ("followup_threshold", self.followup_threshold),
            ("fail_threshold", self.fail_threshold),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")
        if self.followup_threshold > self.fail_threshold:
            raise ValueError("followup_threshold cannot exceed fail_threshold")

    def needs_cwe(self, probability: float) -> bool:
        return probability >= self.followup_threshold

    def decide(self, probability: float) -> Decision:
        if probability >= self.fail_threshold:
            return "fail"
        if probability >= self.followup_threshold:
            return "fail" if self.strict else "warn"
        return "pass"
