from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from .classifier import (
    DEFAULT_MODEL,
    DEFAULT_URL,
    ClassifierError,
    OpenRouterClassifier,
    require_api_key,
)
from .evaluation import run_evaluation, write_evaluation
from .git_diff import GitDiffError, parse_unified_diff, snippets_from_paths, staged_diff
from .models import Snippet
from .policy import Policy
from .report import render_evaluation_summary, render_json, render_text


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    quiet = "--quiet" in arguments
    try:
        if arguments and arguments[0] == "eval":
            return asyncio.run(_eval_command(arguments[1:]))
        return asyncio.run(_scan_command(arguments))
    except KeyboardInterrupt:
        if not quiet:
            print("cancelled", file=sys.stderr)
        return 2


async def _scan_command(argv: list[str]) -> int:
    parser = _common_parser("Classify C/C++ snippets or staged changes")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--stdin", action="store_true", help="read one snippet from stdin")
    source.add_argument("--diff", default="cached", choices=["cached"])
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        api_key = require_api_key()
        policy = _policy(args)
        snippets = _load_scan_snippets(args)
        if not snippets:
            if not args.quiet:
                print(
                    '{"incomplete": false, "results": []}'
                    if args.json
                    else "no C/C++ changes"
                )
            return 0
        async with _classifier(args, api_key) as classifier:
            results = await classifier.classify_many(snippets, policy)
        if not args.quiet:
            print(render_json(results) if args.json else render_text(results))
        return 1 if any(result.decision == "fail" for result in results) else 0
    except (ClassifierError, GitDiffError, OSError, ValueError) as exc:
        return _handle_error(exc, args.on_error, args.json, args.quiet)


async def _eval_command(argv: list[str]) -> int:
    parser = _common_parser("Run the labeled live smoke benchmark")
    parser.set_defaults(concurrency=20)
    parser.add_argument(
        "--fixtures", type=Path, default=Path("tests/fixtures/labeled")
    )
    parser.add_argument("--diagnostic-all-cwes", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        api_key = require_api_key()
        policy = _policy(args)
        async with _classifier(args, api_key) as classifier:
            results, gold, metrics = await run_evaluation(
                classifier,
                args.fixtures,
                policy,
                diagnostic_all_cwes=args.diagnostic_all_cwes,
            )
        outputs = write_evaluation(
            results, gold, metrics, output=args.output, policy=policy
        )
        if args.quiet:
            pass
        elif args.json:
            print(
                json.dumps(
                    {
                        "metrics": metrics,
                        "reports": {
                            "json": str(outputs.json),
                            "html": str(outputs.html),
                        },
                    },
                    indent=2,
                )
            )
        else:
            print(render_text(results))
            print(
                render_evaluation_summary(
                    metrics, json_path=outputs.json, html_path=outputs.html
                )
            )
        return 0
    except (ClassifierError, OSError, ValueError) as exc:
        return _handle_error(exc, args.on_error, args.json, args.quiet)


def _common_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--concurrency",
        type=int,
        default=int(os.environ.get("UNSAFE_C_CONCURRENCY", "16")),
    )
    parser.add_argument(
        "--followup-threshold",
        type=float,
        default=float(os.environ.get("UNSAFE_C_FOLLOWUP_THRESHOLD", "0.60")),
    )
    parser.add_argument(
        "--fail-threshold",
        type=float,
        default=float(os.environ.get("UNSAFE_C_FAIL_THRESHOLD", "0.85")),
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--quiet", action="store_true", help="suppress all terminal output"
    )
    parser.add_argument("--on-error", choices=["block", "warn"], default="block")
    parser.add_argument(
        "--model", default=os.environ.get("UNSAFE_C_MODEL", DEFAULT_MODEL)
    )
    parser.add_argument(
        "--url", default=os.environ.get("UNSAFE_C_OPENROUTER_URL", DEFAULT_URL)
    )
    return parser


def _classifier(args: argparse.Namespace, api_key: str) -> OpenRouterClassifier:
    return OpenRouterClassifier(
        api_key=api_key,
        model=args.model,
        url=args.url,
        concurrency=args.concurrency,
    )


def _policy(args: argparse.Namespace) -> Policy:
    return Policy(
        followup_threshold=args.followup_threshold,
        fail_threshold=args.fail_threshold,
        strict=args.strict,
    )


def _load_scan_snippets(args: argparse.Namespace) -> list[Snippet]:
    if args.stdin:
        code = sys.stdin.read()
        return [
            Snippet(
                identifier="<stdin>",
                path="<stdin>",
                language="c",
                after=code,
            )
        ]
    if args.paths:
        return snippets_from_paths(args.paths)
    return parse_unified_diff(staged_diff())


def _handle_error(
    error: Exception, on_error: str, json_output: bool, quiet: bool
) -> int:
    message = str(error)
    if quiet:
        pass
    elif json_output:
        print(json.dumps({"incomplete": True, "error": message}))
    else:
        print(f"error: {message}", file=sys.stderr)
    return 0 if on_error == "warn" else 2
