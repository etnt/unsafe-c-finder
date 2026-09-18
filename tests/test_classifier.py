from __future__ import annotations

import json

import httpx
import pytest

from unsafe_c_finder.classifier import (
    CWE_CRITERIA,
    ClassifierError,
    OpenRouterClassifier,
)
from unsafe_c_finder.models import Snippet
from unsafe_c_finder.policy import Policy


@pytest.mark.asyncio
async def test_two_stage_classification_only_follows_up_unsafe_snippets() -> None:
    calls: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        calls.append(payload)
        identifier = payload["state"]["path"]
        if "is_unsafe" in payload["questions"]:
            probability = 0.95 if identifier == "unsafe.c" else 0.05
            return httpx.Response(
                200,
                json={
                    "model": "typesafe/jev-1.13",
                    "answers": {
                        "is_unsafe": {"type": "noul", "noul": probability}
                    },
                    "usage": {"input_tokens": 100},
                },
            )
        probabilities = {key: 0.0 for key in CWE_CRITERIA}
        probabilities["cwe_787_121"] = 1.0
        return httpx.Response(
            200,
            json={
                "model": "typesafe/jev-1.13",
                "answers": {
                    "cwe": {
                        "type": "choice",
                        "choice": "cwe_787_121",
                        "probabilities": probabilities,
                    }
                },
                "usage": {"input_tokens": 120},
            },
        )

    snippets = [
        Snippet("1", "unsafe.c", "c", 'strcpy(dst, src);'),
        Snippet("2", "safe.c", "c", 'printf("%s", value);'),
    ]
    transport = httpx.MockTransport(handler)
    async with OpenRouterClassifier(
        api_key="test-key", transport=transport
    ) as classifier:
        results = await classifier.classify_many(snippets, Policy())

    assert len(calls) == 3
    assert results[0].decision == "fail"
    assert results[0].cwe == "cwe_787_121"
    assert results[0].stage2 is not None
    assert results[1].decision == "pass"
    assert results[1].cwe is None
    assert results[1].stage2 is None


@pytest.mark.asyncio
async def test_forced_cwe_identifier_supports_diagnostic_evaluation() -> None:
    question_names: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        question = next(iter(payload["questions"]))
        question_names.append(question)
        if question == "is_unsafe":
            return httpx.Response(
                200,
                json={
                    "model": "typesafe/jev-1.13",
                    "answers": {"is_unsafe": {"type": "noul", "noul": 0.1}},
                },
            )
        probabilities = {key: 0.0 for key in CWE_CRITERIA}
        probabilities["other"] = 1.0
        return httpx.Response(
            200,
            json={
                "model": "typesafe/jev-1.13",
                "answers": {
                    "cwe": {
                        "type": "choice",
                        "choice": "other",
                        "probabilities": probabilities,
                    }
                },
            },
        )

    snippet = Snippet("force-me", "sample.c", "c", "return 0;")
    async with OpenRouterClassifier(
        api_key="test-key", transport=httpx.MockTransport(handler)
    ) as classifier:
        results = await classifier.classify_many(
            [snippet], Policy(), force_cwe_identifiers={"force-me"}
        )

    assert question_names == ["is_unsafe", "cwe"]
    assert results[0].cwe == "other"


@pytest.mark.asyncio
async def test_malformed_probability_is_an_error() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "model": "typesafe/jev-1.13",
                "answers": {"is_unsafe": {"type": "noul", "noul": 1.2}},
            },
        )

    async with OpenRouterClassifier(
        api_key="test-key", transport=httpx.MockTransport(handler)
    ) as classifier:
        with pytest.raises(ClassifierError, match="between 0 and 1"):
            await classifier.classify_many(
                [Snippet("1", "a.c", "c", "return 0;")], Policy()
            )


@pytest.mark.asyncio
async def test_retryable_status_is_retried() -> None:
    attempts = 0

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(
            200,
            json={
                "model": "typesafe/jev-1.13",
                "answers": {"is_unsafe": {"type": "noul", "noul": 0.0}},
            },
        )

    async with OpenRouterClassifier(
        api_key="test-key",
        transport=httpx.MockTransport(handler),
        max_attempts=2,
    ) as classifier:
        results = await classifier.classify_many(
            [Snippet("1", "a.c", "c", "return 0;")], Policy()
        )

    assert attempts == 2
    assert results[0].stage1 is not None
    assert results[0].stage1.attempts == 2
