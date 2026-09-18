from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .classifier import CWE_CRITERIA
from .models import Classification


def render_text(results: Iterable[Classification]) -> str:
    ordered = list(results)
    lines: list[str] = []
    for result in ordered:
        status = {"pass": "ok", "warn": "WARN", "fail": "UNSAFE"}[result.decision]
        detail = ""
        if result.cwe:
            detail = f"  {CWE_CRITERIA[result.cwe]}"
        lines.append(
            f"{status:<6} {result.snippet.identifier}  "
            f"P={result.unsafe_probability:.3f}{detail}"
        )
    counts = Counter(result.decision for result in ordered)
    lines.append(
        f"{counts['fail']} fail, {counts['warn']} warn, {counts['pass']} pass"
    )
    return "\n".join(lines)


def render_json(results: Iterable[Classification], *, incomplete: bool = False) -> str:
    ordered = list(results)
    return json.dumps(
        {
            "incomplete": incomplete,
            "results": [result.to_dict() for result in ordered],
        },
        indent=2,
        sort_keys=True,
    )


def render_evaluation_summary(
    metrics: dict[str, Any], *, json_path: Path, html_path: Path
) -> str:
    followup = metrics["followup"]
    fail = metrics["fail"]
    cwe_accuracy = metrics["cwe_accuracy"]
    cwe_text = (
        "n/a"
        if cwe_accuracy is None
        else f"{cwe_accuracy * 100:5.1f}% ({metrics['cwe_attempts']} classified)"
    )
    models = ", ".join(metrics["models"]) or "unknown"
    return "\n".join(
        [
            "",
            "Evaluation summary",
            "------------------",
            "Threshold   Precision   Recall      F1    TP  FP  TN  FN",
            _metric_row("Follow-up", followup),
            _metric_row("Blocking", fail),
            "",
            f"CWE accuracy       {cwe_text}",
            f"Latency p50/p95    {_ms(metrics['latency_ms_p50'])} / {_ms(metrics['latency_ms_p95'])}",
            f"Requests/retries   {metrics['requests']} / {metrics['retries']}",
            f"Input tokens       {metrics['input_tokens']}",
            f"Model              {models}",
            "",
            "Reports",
            "-------",
            f"JSON  {json_path}",
            f"HTML  {html_path}",
        ]
    )


def _metric_row(label: str, values: dict[str, int | float]) -> str:
    return (
        f"{label:<10}  {values['precision']:>8.3f}  {values['recall']:>7.3f}"
        f"  {values['f1']:>7.3f}  {values['tp']:>3} {values['fp']:>3}"
        f" {values['tn']:>3} {values['fn']:>3}"
    )


def _ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f} ms"
