from __future__ import annotations

import hashlib
import html
import json
import statistics
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .classifier import CWE_CRITERIA, OpenRouterClassifier
from .models import Classification, Snippet
from .policy import Policy


@dataclass(frozen=True, slots=True)
class Gold:
    identifier: str
    path: str
    unsafe: bool
    cwes: tuple[str, ...]
    rationale: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ReportPaths:
    json: Path
    html: Path


def load_fixtures(directory: Path) -> tuple[list[Snippet], dict[str, Gold]]:
    manifest_path = directory / "expected.json"
    try:
        entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load fixture manifest {manifest_path}: {exc}") from exc
    if not isinstance(entries, list):
        raise ValueError("expected.json must contain an array")

    snippets: list[Snippet] = []
    gold: dict[str, Gold] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("fixture entries must be objects")
        if not isinstance(entry.get("unsafe"), bool):
            raise ValueError("fixture unsafe values must be booleans")
        if not isinstance(entry.get("cwes"), list):
            raise ValueError("fixture cwes values must be arrays")
        identifier = str(entry["id"])
        if identifier in gold:
            raise ValueError(f"duplicate fixture id: {identifier}")
        relative_path = str(entry["path"])
        code = (directory / relative_path).read_text(encoding="utf-8")
        cwes = tuple(str(value) for value in entry["cwes"])
        unknown_cwes = set(cwes) - set(CWE_CRITERIA)
        if unknown_cwes:
            raise ValueError(
                f"fixture {identifier} has unknown CWE buckets: "
                f"{', '.join(sorted(unknown_cwes))}"
            )
        if entry["unsafe"] and not cwes:
            raise ValueError(f"unsafe fixture {identifier} must have a CWE bucket")
        if not entry["unsafe"] and cwes:
            raise ValueError(f"safe fixture {identifier} cannot have CWE buckets")
        item = Gold(
            identifier=identifier,
            path=relative_path,
            unsafe=entry["unsafe"],
            cwes=cwes,
            rationale=str(entry["rationale"]),
            sha256=hashlib.sha256(code.encode()).hexdigest(),
        )
        gold[identifier] = item
        snippets.append(
            Snippet(
                identifier=identifier,
                path=relative_path,
                language="c",
                after=code,
                change_kind="snippet",
            )
        )
    return snippets, gold


async def run_evaluation(
    classifier: OpenRouterClassifier,
    fixtures: Path,
    policy: Policy,
    *,
    diagnostic_all_cwes: bool,
) -> tuple[list[Classification], dict[str, Gold], dict[str, Any]]:
    snippets, gold = load_fixtures(fixtures)
    forced = (
        {identifier for identifier, item in gold.items() if item.unsafe}
        if diagnostic_all_cwes
        else None
    )
    results = await classifier.classify_many(
        snippets, policy, force_cwe_identifiers=forced
    )
    metrics = calculate_metrics(results, gold, policy)
    return results, gold, metrics


def calculate_metrics(
    results: list[Classification], gold: dict[str, Gold], policy: Policy
) -> dict[str, Any]:
    def confusion(threshold: float) -> dict[str, int | float]:
        tp = fp = tn = fn = 0
        for result in results:
            expected = gold[result.snippet.identifier].unsafe
            predicted = result.unsafe_probability >= threshold
            tp += int(predicted and expected)
            fp += int(predicted and not expected)
            tn += int(not predicted and not expected)
            fn += int(not predicted and expected)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    cwe_attempts = cwe_hits = 0
    for result in results:
        expected = gold[result.snippet.identifier]
        if expected.unsafe and result.cwe:
            cwe_attempts += 1
            cwe_hits += int(result.cwe in expected.cwes)

    latencies = [
        metadata.latency_ms
        for result in results
        for metadata in (result.stage1, result.stage2)
        if metadata is not None
    ]
    tokens = sum(
        metadata.input_tokens or 0
        for result in results
        for metadata in (result.stage1, result.stage2)
        if metadata is not None
    )
    requests = [
        metadata
        for result in results
        for metadata in (result.stage1, result.stage2)
        if metadata is not None
    ]
    return {
        "followup": confusion(policy.followup_threshold),
        "fail": confusion(policy.fail_threshold),
        "cwe_accuracy": cwe_hits / cwe_attempts if cwe_attempts else None,
        "cwe_attempts": cwe_attempts,
        "latency_ms_p50": statistics.median(latencies) if latencies else None,
        "latency_ms_p95": _percentile(latencies, 0.95),
        "input_tokens": tokens,
        "requests": len(requests),
        "retries": sum(metadata.attempts - 1 for metadata in requests),
        "models": sorted(
            {
                metadata.model
                for result in results
                for metadata in (result.stage1, result.stage2)
                if metadata is not None
            }
        ),
    }


def write_evaluation(
    results: list[Classification],
    gold: dict[str, Gold],
    metrics: dict[str, Any],
    *,
    output: Path | None,
    policy: Policy,
) -> ReportPaths:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    json_path = output or Path.cwd() / f"unsafe-c-finder-eval-{timestamp}.json"
    if json_path.suffix.lower() != ".json":
        json_path = json_path.with_suffix(".json")
    html_path = json_path.with_suffix(".html")
    payload = {
        "timestamp": timestamp,
        "thresholds": {
            "followup": policy.followup_threshold,
            "fail": policy.fail_threshold,
        },
        "metrics": metrics,
        "fixtures": {
            identifier: {
                "path": item.path,
                "unsafe": item.unsafe,
                "cwes": item.cwes,
                "rationale": item.rationale,
                "sha256": item.sha256,
            }
            for identifier, item in gold.items()
        },
        "results": [result.to_dict() for result in results],
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    html_path.write_text(
        _render_html(results, gold, metrics, policy, timestamp), encoding="utf-8"
    )
    return ReportPaths(json=json_path, html=html_path)


def _render_html(
    results: list[Classification],
    gold: dict[str, Gold],
    metrics: dict[str, Any],
    policy: Policy,
    timestamp: str,
) -> str:
    followup = metrics["followup"]
    fail = metrics["fail"]
    cwe_accuracy = metrics["cwe_accuracy"]
    models = ", ".join(metrics["models"]) or "unknown"
    rows: list[str] = []
    for result in results:
        expected = gold[result.snippet.identifier]
        predicted_unsafe = result.unsafe_probability >= policy.followup_threshold
        detection_hit = predicted_unsafe == expected.unsafe
        cwe_hit = (
            result.cwe in expected.cwes
            if expected.unsafe and result.cwe is not None
            else None
        )
        status_class = {
            "fail": "status-fail",
            "warn": "status-warn",
            "pass": "status-pass",
        }[result.decision]
        cwe_label = CWE_CRITERIA.get(result.cwe or "", "Not requested")
        cwe_result = (
            '<span class="hit">match</span>'
            if cwe_hit is True
            else '<span class="miss">mismatch</span>'
            if cwe_hit is False
            else '<span class="muted">n/a</span>'
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(result.snippet.identifier)}</td>"
            f"<td><code>{html.escape(expected.path)}</code></td>"
            f"<td>{'Unsafe' if expected.unsafe else 'Safe'}</td>"
            f'<td><span class="pill {status_class}">{html.escape(result.decision.upper())}</span></td>'
            "<td>"
            f'<div class="probability"><span style="width:{result.unsafe_probability * 100:.1f}%"></span></div>'
            f"{result.unsafe_probability:.3f}"
            "</td>"
            f"<td>{html.escape(cwe_label)}</td>"
            f"<td>{'yes' if detection_hit else 'no'}</td>"
            f"<td>{cwe_result}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>unsafe-c-finder evaluation</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #090d16;
      --panel: #111827;
      --panel-2: #172033;
      --border: #26334d;
      --text: #e8edf6;
      --muted: #94a3b8;
      --green: #34d399;
      --yellow: #fbbf24;
      --red: #fb7185;
      --blue: #60a5fa;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background:
        radial-gradient(circle at top left, #172554 0, transparent 32rem),
        var(--bg);
      color: var(--text);
      font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    main {{ width: min(1400px, calc(100% - 32px)); margin: 0 auto; padding: 44px 0 64px; }}
    h1 {{ margin: 0; font-size: clamp(28px, 4vw, 44px); letter-spacing: -0.04em; }}
    .subtitle {{ color: var(--muted); margin: 8px 0 28px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; }}
    .card, .table-wrap {{
      background: color-mix(in srgb, var(--panel) 92%, transparent);
      border: 1px solid var(--border);
      border-radius: 14px;
      box-shadow: 0 18px 50px rgb(0 0 0 / 20%);
    }}
    .card {{ padding: 18px; }}
    .card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
    .card .value {{ margin-top: 5px; font-size: 26px; font-weight: 750; }}
    .card .detail {{ color: var(--muted); margin-top: 3px; font-size: 12px; }}
    h2 {{ margin: 34px 0 12px; font-size: 18px; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 980px; }}
    th, td {{ padding: 12px 14px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: middle; }}
    th {{ color: var(--muted); background: var(--panel-2); font-size: 11px; text-transform: uppercase; letter-spacing: .07em; }}
    tbody tr:hover {{ background: rgb(96 165 250 / 5%); }}
    tbody tr:last-child td {{ border-bottom: 0; }}
    code {{ color: #bfdbfe; }}
    .pill {{ display: inline-block; min-width: 62px; padding: 3px 9px; border-radius: 999px; text-align: center; font-size: 11px; font-weight: 800; }}
    .status-pass {{ color: var(--green); background: rgb(52 211 153 / 12%); }}
    .status-warn {{ color: var(--yellow); background: rgb(251 191 36 / 12%); }}
    .status-fail {{ color: var(--red); background: rgb(251 113 133 / 12%); }}
    .probability {{ display: inline-block; width: 72px; height: 7px; margin-right: 8px; overflow: hidden; border-radius: 99px; background: #26334d; vertical-align: middle; }}
    .probability span {{ display: block; height: 100%; background: linear-gradient(90deg, var(--blue), var(--red)); }}
    .hit {{ color: var(--green); font-weight: 700; }}
    .miss {{ color: var(--red); font-weight: 700; }}
    .muted, footer {{ color: var(--muted); }}
    footer {{ margin-top: 18px; font-size: 12px; }}
  </style>
</head>
<body>
<main>
  <h1>Unsafe C/C++ Evaluation</h1>
  <p class="subtitle">Generated {html.escape(timestamp)} · model {html.escape(models)}</p>
  <section class="cards">
    <div class="card">
      <div class="label">Follow-up F1</div>
      <div class="value">{followup['f1']:.3f}</div>
      <div class="detail">P {followup['precision']:.3f} · R {followup['recall']:.3f}</div>
    </div>
    <div class="card">
      <div class="label">Blocking F1</div>
      <div class="value">{fail['f1']:.3f}</div>
      <div class="detail">P {fail['precision']:.3f} · R {fail['recall']:.3f}</div>
    </div>
    <div class="card">
      <div class="label">CWE accuracy</div>
      <div class="value">{_metric(cwe_accuracy)}</div>
      <div class="detail">{metrics['cwe_attempts']} unsafe classifications</div>
    </div>
    <div class="card">
      <div class="label">Latency p50 / p95</div>
      <div class="value">{_milliseconds(metrics['latency_ms_p50'])}</div>
      <div class="detail">p95 {_milliseconds(metrics['latency_ms_p95'])}</div>
    </div>
    <div class="card">
      <div class="label">Requests / retries</div>
      <div class="value">{metrics['requests']}</div>
      <div class="detail">{metrics['retries']} retries · {metrics['input_tokens']} input tokens</div>
    </div>
  </section>
  <h2>Snippet results</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>ID</th><th>Fixture</th><th>Gold</th><th>Decision</th><th>Unsafe probability</th><th>CWE bucket</th><th>Detection</th><th>CWE</th></tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>
  <footer>
    Follow-up threshold {policy.followup_threshold:.2f} · blocking threshold {policy.fail_threshold:.2f}.
    This synthetic smoke benchmark is not a production-quality estimate.
  </footer>
</main>
</body>
</html>
"""


def _metric(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _milliseconds(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0f} ms"


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(round((len(ordered) - 1) * fraction), len(ordered) - 1)
    return ordered[index]
