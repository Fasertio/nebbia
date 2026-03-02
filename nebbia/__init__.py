"""
nebbia
===============
LDAP filter obfuscation tool.

Usage:
---------------
>>> from nebbia import obfuscate
>>> obfuscate("(&(uid=jdoe)(objectClass=person))")
'(&(oBjEcTcLaSs=\\\\70\\\\65\\\\72\\\\73\\\\6F\\\\6E)(uId=\\\\6A\\\\64\\\\6F\\\\65))'

>>> from nebbia import parse, serialize
>>> ast = parse("(uid=admin)")
>>> serialize(ast)
'(uid=admin)'
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

__version__ = "1.0.0"
__author__  = "Fasertio"
