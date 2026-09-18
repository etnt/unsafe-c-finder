from pathlib import Path

from unsafe_c_finder.evaluation import (
    calculate_metrics,
    load_fixtures,
    write_evaluation,
)
from unsafe_c_finder.models import Classification
from unsafe_c_finder.policy import Policy

FIXTURES = Path(__file__).parent / "fixtures" / "labeled"


def test_load_twenty_balanced_fixtures() -> None:
    snippets, gold = load_fixtures(FIXTURES)

    assert len(snippets) == 20
    assert sum(item.unsafe for item in gold.values()) == 10
    assert all(len(item.sha256) == 64 for item in gold.values())


def test_metrics_count_detection_and_cwe_accuracy() -> None:
    snippets, gold = load_fixtures(FIXTURES)
    results = []
    for snippet in snippets:
        expected = gold[snippet.identifier]
        results.append(
            Classification(
                snippet=snippet,
                unsafe_probability=0.9 if expected.unsafe else 0.1,
                decision="fail" if expected.unsafe else "pass",
                cwe=expected.cwes[0] if expected.cwes else None,
            )
        )

    metrics = calculate_metrics(results, gold, Policy())

    assert metrics["fail"]["f1"] == 1.0
    assert metrics["cwe_accuracy"] == 1.0


def test_serialized_results_do_not_include_source_code() -> None:
    snippets, _ = load_fixtures(FIXTURES)
    result = Classification(
        snippet=snippets[0],
        unsafe_probability=0.9,
        decision="fail",
        cwe="cwe_787_121",
    )

    serialized = result.to_dict()

    assert "after" not in serialized["snippet"]
    assert "before" not in serialized["snippet"]
    assert "context" not in serialized["snippet"]


def test_write_evaluation_creates_json_and_html_in_current_directory(
    tmp_path, monkeypatch
) -> None:
    snippets, gold = load_fixtures(FIXTURES)
    results = [
        Classification(
            snippet=snippet,
            unsafe_probability=0.9 if gold[snippet.identifier].unsafe else 0.1,
            decision="fail" if gold[snippet.identifier].unsafe else "pass",
            cwe=(
                gold[snippet.identifier].cwes[0]
                if gold[snippet.identifier].cwes
                else None
            ),
        )
        for snippet in snippets
    ]
    policy = Policy()
    metrics = calculate_metrics(results, gold, policy)
    monkeypatch.chdir(tmp_path)

    paths = write_evaluation(results, gold, metrics, output=None, policy=policy)

    assert paths.json.parent == tmp_path
    assert paths.html.parent == tmp_path
    assert paths.json.exists()
    assert paths.html.exists()
    assert "Unsafe C/C++ Evaluation" in paths.html.read_text(encoding="utf-8")
    assert "01_strcpy_overflow.c" in paths.html.read_text(encoding="utf-8")


def test_custom_json_output_uses_matching_html_stem(tmp_path) -> None:
    snippets, gold = load_fixtures(FIXTURES)
    results = [
        Classification(
            snippet=snippets[0],
            unsafe_probability=0.9,
            decision="fail",
            cwe=gold["01"].cwes[0],
        )
    ]
    metrics = calculate_metrics(results, {"01": gold["01"]}, Policy())

    paths = write_evaluation(
        results,
        {"01": gold["01"]},
        metrics,
        output=tmp_path / "custom-report.json",
        policy=Policy(),
    )

    assert paths.json == tmp_path / "custom-report.json"
    assert paths.html == tmp_path / "custom-report.html"
