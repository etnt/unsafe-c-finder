import pytest

from unsafe_c_finder.policy import Policy


@pytest.mark.parametrize(
    ("probability", "decision", "needs_cwe"),
    [
        (0.0, "pass", False),
        (0.599, "pass", False),
        (0.60, "warn", True),
        (0.849, "warn", True),
        (0.85, "fail", True),
        (1.0, "fail", True),
    ],
)
def test_policy(probability: float, decision: str, needs_cwe: bool) -> None:
    policy = Policy()

    assert policy.decide(probability) == decision
    assert policy.needs_cwe(probability) is needs_cwe


def test_strict_promotes_warning_to_failure() -> None:
    assert Policy(strict=True).decide(0.60) == "fail"


@pytest.mark.parametrize(
    ("followup", "fail"),
    [(-0.1, 0.8), (0.2, 1.1), (0.9, 0.8)],
)
def test_invalid_thresholds(followup: float, fail: float) -> None:
    with pytest.raises(ValueError):
        Policy(followup_threshold=followup, fail_threshold=fail)
