#!/usr/bin/env python3
"""Atheris fuzz harness template (language: python).

Copy to harnesses/<id>/<name>_fuzz.py, set dest to a path INSIDE the
target clone (so imports resolve), and point run_one() at the pure
function under test. Run via `make fuzz-<id>` (timeout-bounded) or:
    .fuzzvenv/bin/python <dest> -atheris_runs=0
Crashers are written to the CWD as crash-* / poc-* files.
"""

import contextlib
import sys

import atheris

with atheris.instrument_imports():
    # import the module under test here, e.g.:
    # from app import parser
    pass


def run_one(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    s = fdp.ConsumeUnicodeNoSurrogates(4096)
    with contextlib.suppress(ValueError, KeyError, TypeError):  # expected parse errors not findings
        # parser.parse(s)   # <- call the target function
        _ = s


def main() -> None:
    atheris.Setup(sys.argv, run_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
