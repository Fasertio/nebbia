"""
Entrypoint CLI per nebbia.

Utilizzo
--------
    # via modulo diretto
    python -m nebbia "(uid=jdoe)"

    # dopo installazione pip
    nebbia "(uid=jdoe)"
    nebbia "(uid=jdoe)" --count 3
    nebbia "(uid=jdoe)" --seed 42
    nebbia --demo
"""

from __future__ import annotations

import argparse
import sys

from .core import LDAPParseError, obfuscate

# ── query di esempio per --demo ─────────────────────────────────────────
_DEMO_QUERIES = [
    "(uid=jdoe)",
    "(&(objectClass=person)(uid=john)(!(locked=true)))",
    "(|(cn=Alice)(cn=Bob)(cn=Charlie))",
    "(&(objectClass=user)(|(department=IT)(department=HR))(!(disabled=TRUE)))",
    "(sAMAccountName=krbtgt)",
    "(&(distinguishedName=CN=krbtgt,CN=Users,DC=company-b,DC=local))",
]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nebbia",
        description=(
            "Offusca una query LDAP mantenendone la semantica invariata.\n"
            "Applica trasformazioni strutturali (doppia negazione, shuffle)\n"
            "e lessicali (mixed-case, escape \\HH) sull'AST del filtro."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Esempi:\n"
            '  nebbia "(uid=jdoe)"\n'
            '  nebbia "(&(uid=admin)(objectClass=person))" --count 3\n'
            '  nebbia "(cn=krbtgt)" --seed 42 --no-color\n'
            "  nebbia --demo"
        ),
    )
    p.add_argument(
        "query",
        nargs="?",
        help="Filtro LDAP da offuscare (RFC 4515).",
    )
    p.add_argument(
        "-c", "--count",
        type=int,
        default=1,
        metavar="N",
        help="Numero di varianti da generare (default: 1).",
    )
    p.add_argument(
        "-s", "--seed",
        type=int,
        default=None,
        metavar="SEED",
        help="Seme per output deterministico.",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disabilita l'output colorato ANSI.",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="Esegui le query di esempio predefinite.",
    )
    p.add_argument(
        "-V", "--version",
        action="version",
        version="nebbia 1.0.0",
    )
    return p


# ── helpers ANSI ─────────────────────────────────────────────────────────

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
    """Stampa le varianti offuscate di una singola query. Ritorna 0/1."""
    sep = _c("─" * 60, _DIM, use_color=use_color)
    print(sep)
    print(_c("ORIGINALE  ", _BOLD, _CYAN, use_color=use_color) + query)

    ok = True
    for i in range(1, count + 1):
        current_seed = None if seed is None else seed + i - 1
        try:
            result = obfuscate(query, seed=current_seed)
            label  = f"OFFUSCATA {i}" if count > 1 else "OFFUSCATA "
            print(_c(f"{label:<11}", _BOLD, _GREEN, use_color=use_color) + result)
        except LDAPParseError as exc:
            print(_c("ERRORE     ", _BOLD, _RED, use_color=use_color) + str(exc))
            ok = False
            break

    return 0 if ok else 1


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    use_color = not args.no_color and sys.stdout.isatty()

    # ── modalità demo ────────────────────────────────────────────────────
    if args.demo:
        header = _c(" LDAP Obfuscator — Demo ", _BOLD, _CYAN, use_color=use_color)
        print(f"\n{header}\n")
        exit_code = 0
        for q in _DEMO_QUERIES:
            rc = _run_query(q, count=2, seed=args.seed, use_color=use_color)
            if rc:
                exit_code = rc
        print(_c("─" * 60, _DIM, use_color=use_color))
        sys.exit(exit_code)

    # ── query singola passata come argomento ─────────────────────────────
    if args.query:
        rc = _run_query(args.query, count=args.count, seed=args.seed, use_color=use_color)
        sys.exit(rc)

    # ── lettura da stdin (pipe) ───────────────────────────────────────────
    if not sys.stdin.isatty():
        exit_code = 0
        for line in sys.stdin:
            line = line.strip()
            if line:
                rc = _run_query(line, count=args.count, seed=args.seed, use_color=use_color)
                if rc:
                    exit_code = rc
        sys.exit(exit_code)

    # ── nessun input ─────────────────────────────────────────────────────
    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
