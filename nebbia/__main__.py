"""
Entrypoint CLI.

Usage
--------
    # via module
    python -m nebbia "(uid=jdoe)"

    # pip installation
    nebbia "(uid=jdoe)"
    nebbia "(uid=jdoe)" --count 3
    nebbia "(uid=jdoe)" --seed 42
    nebbia --demo
"""

from __future__ import annotations

import argparse
import sys

from .core import LDAPParseError, obfuscate


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nebbia",
        description=(
            "LDAP filter obfuscation tool.\n"
            "Structural AST transformation applied."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example of usage:\n"
            '  nebbia "(uid=jdoe)"\n'
            '  nebbia "(&(uid=admin)(objectClass=person))" --count 3\n'
            '  nebbia "(cn=krbtgt)" --seed 42 --no-color'
        ),
    )
    p.add_argument(
        "query",
        nargs="?",
        help="LDAP filter.",
    )
    p.add_argument(
        "-c", "--count",
        type=int,
        default=1,
        metavar="N",
        help="Number of variant (default: 1).",
    )
    p.add_argument(
        "-s", "--seed",
        type=int,
        default=None,
        metavar="SEED",
        help="Output seed.",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable color output ANSI.",
    )
    p.add_argument(
        "-V", "--version",
        action="version",
        version="nebbia 1.0.0",
    )
    return p


_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_CYAN   = "\033[36m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_DIM    = "\033[2m"


def _c(text: str, *codes: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return "".join(codes) + text + _RESET


def _run_query(
    query: str,
    count: int,
    seed: int | None,
    use_color: bool,
) -> int:
    """Obfuscated variables for single query"""
    sep = _c("─" * 60, _DIM, use_color=use_color)
    print(sep)
    print(_c("INPUT  ", _BOLD, _CYAN, use_color=use_color) + query)

    ok = True
    for i in range(1, count + 1):
        current_seed = None if seed is None else seed + i - 1
        try:
            result = obfuscate(query, seed=current_seed)
            label  = f"RESULT {i}" if count > 1 else "RESULT "
            print(_c(f"{label:<11}", _BOLD, _GREEN, use_color=use_color) + result)
        except LDAPParseError as exc:
            print(_c("ERROR     ", _BOLD, _RED, use_color=use_color) + str(exc))
            ok = False
            break

    return 0 if ok else 1


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    use_color = not args.no_color and sys.stdout.isatty()

    if args.query:
        rc = _run_query(args.query, count=args.count, seed=args.seed, use_color=use_color)
        sys.exit(rc)

    #stdin
    if not sys.stdin.isatty():
        exit_code = 0
        for line in sys.stdin:
            line = line.strip()
            if line:
                rc = _run_query(line, count=args.count, seed=args.seed, use_color=use_color)
                if rc:
                    exit_code = rc
        sys.exit(exit_code)

    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
