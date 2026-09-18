# unsafe-c-finder

`unsafe-c-finder` classifies C/C++ snippets and staged git diff hunks with
TypeSafe Jev through OpenRouter. It first asks for the probability that a
change is unsafe, then asks for a CWE bucket only when that probability crosses
the follow-up threshold.

## Setup

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
export OPENROUTER_API_KEY='...'
```

The API key is read only from `OPENROUTER_API_KEY`. Source code is sent to
OpenRouter, so use the tool only where that is permitted.

## Usage

```sh
# Classify the staged C/C++ diff
unsafe-c-finder

# Classify one snippet
printf 'void f(char *s) { char b[8]; strcpy(b, s); }\n' |
  unsafe-c-finder --stdin

# Run the 20-snippet live smoke benchmark
unsafe-c-finder eval --fixtures tests/fixtures/labeled --concurrency 20
```

The eval command writes two timestamped reports in the current directory:

```text
unsafe-c-finder-eval-YYYYMMDDTHHMMSSZ.json
unsafe-c-finder-eval-YYYYMMDDTHHMMSSZ.html
```

Use `--output my-report.json` to select the JSON path; the HTML report is
written next to it as `my-report.html`.

Normal eval output is a readable text summary. Use `--json` for machine-readable
terminal output or `--quiet` to suppress terminal output entirely while still
writing both report files.

The OpenRouter decisions endpoint is currently configurable because its API is
alpha:

```sh
export UNSAFE_C_MODEL='~typesafe/jev-latest'
export UNSAFE_C_OPENROUTER_URL='https://openrouter.ai/api/alpha/decisions'
```

Exit status is `0` for no blocking finding, `1` for a blocking finding, and `2`
for configuration, git, network, or response errors. API errors fail closed by
default; `--on-error warn` is an explicit local-only fail-open mode.

## Example

```sh
❯ time unsafe-c-finder eval --fixtures tests/fixtures/labeled --concurrency 20
UNSAFE 01  P=0.960  CWE-787 / CWE-121: Out-of-Bounds Write (Buffer Overflow)
UNSAFE 02  P=0.980  CWE-416: Use-After-Free
UNSAFE 03  P=0.870  CWE-125: Out-of-Bounds Read
UNSAFE 04  P=0.880  CWE-476: Null Pointer Dereference
WARN   05  P=0.720  CWE-190: Integer Overflow or Wraparound
UNSAFE 06  P=0.890  CWE-457: Use of Uninitialized Variable
UNSAFE 07  P=0.970  CWE-78 / CWE-134: Command / Format String Injection
UNSAFE 08  P=0.950  CWE-401 / CWE-772: Memory Leak / Missing Release of Resource
UNSAFE 09  P=0.970  CWE-415: Double Free
WARN   10  P=0.610  CWE-327: Use of Broken or Risky Cryptographic Algorithm
ok     11  P=0.550
ok     12  P=0.450
ok     13  P=0.150
ok     14  P=0.060
ok     15  P=0.140
ok     16  P=0.030
ok     17  P=0.350
ok     18  P=0.090
ok     19  P=0.290
ok     20  P=0.210
8 fail, 2 warn, 10 pass

Evaluation summary
------------------
Threshold   Precision   Recall      F1    TP  FP  TN  FN
Follow-up      1.000    1.000    1.000   10   0  10   0
Blocking       1.000    0.800    0.889    8   0  10   2

CWE accuracy       100.0% (10 classified)
Latency p50/p95    421 ms / 1108 ms
Requests/retries   30 / 0
Input tokens       17245
Model              typesafe/jev-1.13-20260917

Reports
-------
JSON  /Users/ttornkvi/git/unsafe-c-finder/unsafe-c-finder-eval-20260918T185357Z.json
HTML  /Users/ttornkvi/git/unsafe-c-finder/unsafe-c-finder-eval-20260918T185357Z.html

real    0m1.936s
user    0m0.289s
sys     0m0.071s
```

## Licence

MPL-2.0
