from pathlib import Path

from unsafe_c_finder.report import render_evaluation_summary


def test_evaluation_summary_is_readable_text() -> None:
    metrics = {
        "followup": {
            "precision": 0.9,
            "recall": 1.0,
            "f1": 0.947,
            "tp": 10,
            "fp": 1,
            "tn": 9,
            "fn": 0,
        },
        "fail": {
            "precision": 1.0,
            "recall": 0.8,
            "f1": 0.889,
            "tp": 8,
            "fp": 0,
            "tn": 10,
            "fn": 2,
        },
        "cwe_accuracy": 1.0,
        "cwe_attempts": 10,
        "latency_ms_p50": 500.0,
        "latency_ms_p95": 900.0,
        "requests": 30,
        "retries": 1,
        "input_tokens": 17000,
        "models": ["typesafe/jev-1.13"],
    }

    output = render_evaluation_summary(
        metrics, json_path=Path("report.json"), html_path=Path("report.html")
    )

    assert "Evaluation summary" in output
    assert "Threshold   Precision" in output
    assert "Follow-up" in output
    assert "report.html" in output
    assert not output.lstrip().startswith("{")
