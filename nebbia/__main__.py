"""
Entrypoint CLI for nebbia.

Usage
-----
    python -m nebbia "(uid=jdoe)"
    nebbia "(uid=jdoe)"
    nebbia "(uid=jdoe)" --count 3
    nebbia "(uid=jdoe)" --seed 42
    nebbia --demo
    echo "(uid=jdoe)" | nebbia
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core import LDAPParseError, obfuscate


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nebbia",
        description=(
            "LDAP filter obfuscation tool.\n"
            "Applies structural AST transformations and lexical encoding."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            '  nebbia "(uid=jdoe)"\n'
            '  nebbia "(&(uid=admin)(objectClass=person))" --count 3\n'
            '  nebbia "(cn=krbtgt)" --seed 42 --no-color\n'
            "  nebbia --demo\n"
            '  echo "(uid=jdoe)" | nebbia'
        ),
    )
    p.add_argument(
        "query",
        nargs="?",
        help="LDAP filter to obfuscate.",
    )
    p.add_argument(
        "-c", "--count",
        type=int,
        default=1,
        metavar="N",
        help="Number of variants to produce (default: 1).",
    )
    p.add_argument(
        "-s", "--seed",
        type=int,
        default=None,
        metavar="SEED",
        help="PRNG seed for reproducible output.",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Show built-in obfuscation examples and exit.",
    )
    p.add_argument(
        "-V", "--version",
        action="version",
        version=f"nebbia {__version__}",
    )
    return p


# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_CYAN   = "\033[36m"
_GREEN  = "\033[32m"
_RED    = "\033[31m"
_DIM    = "\033[2m"


def _c(text: str, *codes: str, use_color: bool = True) -> str:
    """Wrap *text* in ANSI escape codes when *use_color* is True."""
    if not use_color:
        return text
    return "".join(codes) + text + _RESET


# ---------------------------------------------------------------------------
# Query runner
# ---------------------------------------------------------------------------

# Filters used by --demo
_DEMO_QUERIES: list[str] = [
    "(uid=jdoe)",
    "(cn=Administrator)",
    "(&(uid=admin)(objectClass=person))",
    "(|(cn=Alice)(cn=Bob)(cn=Eve))",
    "(&(objectClass=user)(mail=*)(!(uid=guest)))",
    "(&(sAMAccountName=krbtgt)(objectClass=user))",
]


def _run_query(
    query: str,
    count: int,
    seed: int | None,
    use_color: bool,
) -> int:
    """
    Obfuscate *query* and print the result(s).

    Returns 0 on success, 1 if a parse error occurs.
    """
    sep = _c("─" * 60, _DIM, use_color=use_color)
    print(sep)
    print(_c("INPUT  ", _BOLD, _CYAN, use_color=use_color) + query)

    for i in range(1, count + 1):
        current_seed = None if seed is None else seed + i - 1
        try:
            result = obfuscate(query, seed=current_seed)
            label  = f"RESULT {i}" if count > 1 else "RESULT "
            print(_c(f"{label:<11}", _BOLD, _GREEN, use_color=use_color) + result)
        except LDAPParseError as exc:
            print(_c("ERROR      ", _BOLD, _RED, use_color=use_color) + str(exc))
            return 1

    return 0


def _run_demo(use_color: bool) -> None:
    """Print obfuscation examples for the built-in set of LDAP filters."""
    title = " nebbia – obfuscation demo "
    print(_c("=" * 60, _DIM, use_color=use_color))
    print(_c(title, _BOLD, _CYAN, use_color=use_color))
    for query in _DEMO_QUERIES:
        _run_query(query, count=1, seed=None, use_color=use_color)
    print(_c("─" * 60, _DIM, use_color=use_color))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser    = _build_parser()
    args      = parser.parse_args(argv)
    use_color = not args.no_color and sys.stdout.isatty()

    if args.demo:
        _run_demo(use_color)
        sys.exit(0)

    if args.query:
        rc = _run_query(
            args.query,
            count=args.count,
            seed=args.seed,
            use_color=use_color,
        )
        sys.exit(rc)

    # Read from stdin when piped
    if not sys.stdin.isatty():
        exit_code = 0
        for line in sys.stdin:
            line = line.strip()
            if line:
                rc = _run_query(
                    line,
                    count=args.count,
                    seed=args.seed,
                    use_color=use_color,
                )
                if rc:
                    exit_code = rc
        sys.exit(exit_code)

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
