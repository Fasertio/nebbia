"""
nebbia
======
LDAP filter obfuscation tool.

Applies structural AST transformations and lexical encoding to produce
filters that are semantically equivalent to the input but visually distinct.

Examples
--------
    from nebbia import obfuscate

    obfuscate("(uid=jdoe)")
    # e.g. '(uId=\\6a\\64\\6f\\65)'

    obfuscate("(&(uid=admin)(objectClass=person))")
    # e.g. '(&(2.5.4.0=\\70\\65\\72\\73\\6F\\6e)((!(!( uId=\\61\\64\\6d\\69\\6e))))'

    from nebbia import parse, serialize
    ast = parse("(uid=admin)")
    serialize(ast)
    # '(uid=admin)'
"""

from .core import (
    ASTNode,
    LDAPParseError,
    NodeType,
    obfuscate,
    parse,
    serialize,
)

__all__ = [
    "obfuscate",
    "parse",
    "serialize",
    "ASTNode",
    "NodeType",
    "LDAPParseError",
]

__version__ = "1.2.0"
__author__  = "Fasertio"
