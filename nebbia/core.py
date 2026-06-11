"""
nebbia.core  -  LDAP filter obfuscation engine
"""

from __future__ import annotations

import re
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------

class NodeType(Enum):
    AND     = auto()
    OR      = auto()
    NOT     = auto()
    FILTER  = auto()   # (attr op value)
    PRESENT = auto()   # (attr=*)


@dataclass
class ASTNode:
    type:      NodeType
    children:  list[ASTNode] = field(default_factory=list)
    attribute: Optional[str] = None
    operator:  Optional[str] = None
    value:     Optional[str] = None

    def __repr__(self) -> str:
        if self.type == NodeType.FILTER:
            return f"ASTNode(FILTER, {self.attribute!r}{self.operator}{self.value!r})"
        if self.type == NodeType.PRESENT:
            return f"ASTNode(PRESENT, {self.attribute!r}=*)"
        return f"ASTNode({self.type.name}, children={len(self.children)})"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class LDAPParseError(ValueError):
    """Raised when the input is not a valid LDAP filter."""


class LDAPParser:
    """
    Recursive-descent parser for LDAP filter strings (RFC 4515).

    Supported grammar:
        filter      = "(" filtercomp ")"
        filtercomp  = and / or / not / item
        and         = "&" filterlist
        or          = "|" filterlist
        not         = "!" filter
        filterlist  = 1*filter
        item        = simple / present
        simple      = attr filtertype assertionvalue
        filtertype  = "=" / ">=" / "<=" / "~="
        present     = attr "=*"
        assertionvalue = *( normal / escaped )
        escaped     = "\\" 2HEXDIG

    Note: extensible match rules (:=) are not supported.
    """

    _PRESENT_RE = re.compile(r"^([^=<>~!()\\]+)=\*$")
    _SIMPLE_RE  = re.compile(r"^([^=<>~!()\\]+)(>=|<=|~=|=)(.*)$", re.DOTALL)

    def __init__(self, query: str) -> None:
        self.src = query.strip()
        self.pos = 0

    # ---- primitives --------------------------------------------------------

    def _peek(self) -> str:
        return self.src[self.pos] if self.pos < len(self.src) else ""

    def _consume(self, ch: str) -> None:
        if self.pos >= len(self.src):
            raise LDAPParseError(f"Unexpected end of input; expected '{ch}'")
        if self.src[self.pos] != ch:
            ctx = self.src[max(0, self.pos - 5) : self.pos + 5]
            raise LDAPParseError(
                f"Expected '{ch}', found '{self.src[self.pos]}' "
                f"at pos {self.pos} (context: '…{ctx}…')"
            )
        self.pos += 1

    # ---- grammar -----------------------------------------------------------

    def parse(self) -> ASTNode:
        node = self._parse_filter()
        if self.pos != len(self.src):
            raise LDAPParseError(
                f"Trailing characters at pos {self.pos}: '{self.src[self.pos:]}'"
            )
        return node

    def _parse_filter(self) -> ASTNode:
        self._consume("(")
        ch = self._peek()
        if ch == "&":
            node = self._parse_compound(NodeType.AND)
        elif ch == "|":
            node = self._parse_compound(NodeType.OR)
        elif ch == "!":
            node = self._parse_not()
        else:
            node = self._parse_simple()
        self._consume(")")
        return node

    def _parse_compound(self, ntype: NodeType) -> ASTNode:
        self.pos += 1  # skip '&' or '|'
        node = ASTNode(type=ntype)
        while self._peek() == "(":
            node.children.append(self._parse_filter())
        return node

    def _parse_not(self) -> ASTNode:
        self.pos += 1  # skip '!'
        return ASTNode(type=NodeType.NOT, children=[self._parse_filter()])

    def _parse_simple(self) -> ASTNode:
        """
        Parse a simple assertion.

        Scans forward respecting \\XX-escaped bytes so that a literal ')'
        encoded as \\29 is never mistaken for the filter's closing parenthesis.
        """
        start = i = self.pos
        while i < len(self.src):
            c = self.src[i]
            if c == "\\" and i + 2 < len(self.src):
                i += 3          # skip backslash + two hex digits
                continue
            if c == ")":
                break
            i += 1
        else:
            raise LDAPParseError("Missing closing ')' for simple filter")

        expr     = self.src[start:i]
        self.pos = i            # the outer _parse_filter will consume ')'

        m = self._PRESENT_RE.match(expr)
        if m:
            return ASTNode(type=NodeType.PRESENT, attribute=m.group(1))

        m = self._SIMPLE_RE.match(expr)
        if m:
            return ASTNode(
                type=NodeType.FILTER,
                attribute=m.group(1),
                operator=m.group(2),
                value=m.group(3),
            )

        raise LDAPParseError(f"Unrecognised simple filter: '{expr}'")


# ---------------------------------------------------------------------------
# Lexical obfuscation helpers
# ---------------------------------------------------------------------------

# Map of well-known attribute names (lowercase key) → numeric OID.
# RFC 4511-compliant servers treat descriptive names and OIDs as equivalent.
_ATTR_OIDS: dict[str, str] = {
    # Core schema — RFC 4519 / X.520
    "objectclass":          "2.5.4.0",
    "cn":                   "2.5.4.3",
    "sn":                   "2.5.4.4",
    "c":                    "2.5.4.6",
    "l":                    "2.5.4.7",
    "st":                   "2.5.4.8",
    "o":                    "2.5.4.10",
    "ou":                   "2.5.4.11",
    "title":                "2.5.4.12",
    "member":               "2.5.4.31",
    "givenname":            "2.5.4.42",
    # COSINE / inetOrgPerson — RFC 4524 / RFC 2798
    "uid":                  "0.9.2342.19200300.100.1.1",
    "mail":                 "0.9.2342.19200300.100.1.3",
    # Active Directory extensions
    "samaccountname":       "1.2.840.113556.1.4.221",
    "memberof":             "1.2.840.113556.1.4.222",
    "userprincipalname":    "1.2.840.113556.1.4.656",
    "useraccountcontrol":   "1.2.840.113556.1.4.8",
}

# Matches pre-existing \XX escape sequences inside assertion values.
_ESCAPE_RE = re.compile(r"\\[0-9a-fA-F]{2}")


def _hex_nibble(n: int) -> str:
    """Return a randomly-cased hex character for nibble *n* (0–15)."""
    c = format(n & 0xF, "X")
    return c.lower() if random.random() < 0.5 else c


def _hex_escape_char(c: str) -> str:
    """LDAP-escape one character as \\XY with randomly-cased hex digits."""
    b = ord(c)
    return f"\\{_hex_nibble(b >> 4)}{_hex_nibble(b & 0xF)}"


def _hex_encode_full(value: str) -> str:
    """Encode every character as \\XY."""
    return "".join(_hex_escape_char(c) for c in value)


def _hex_encode_partial(value: str) -> str:
    """Encode alphanumeric characters with ~65 % probability; leave the rest."""
    return "".join(
        _hex_escape_char(c) if c.isalnum() and random.random() > 0.35 else c
        for c in value
    )


def _hex_encode_scattered(value: str) -> str:
    """Encode each character with ~50 % probability regardless of type."""
    return "".join(
        _hex_escape_char(c) if random.random() > 0.5 else c
        for c in value
    )


def _encode_literal(seg: str) -> str:
    """Apply a random encoding strategy to a wildcard-free segment."""
    if not seg:
        return seg
    strategy = random.choice(("plain", "full_hex", "partial_hex", "scattered_hex"))
    if strategy == "full_hex":
        return _hex_encode_full(seg)
    if strategy == "partial_hex":
        return _hex_encode_partial(seg)
    if strategy == "scattered_hex":
        return _hex_encode_scattered(seg)
    return seg  # "plain"


def _obfuscate_value(value: str) -> str:
    """
    Apply a randomly chosen encoding strategy to *value*.

    Two special cases are handled conservatively:

    * Values that already contain ``\\XX`` escape sequences are left unchanged
      to prevent double-encoding from altering their semantics.
    * Values that contain ``*`` (LDAP wildcard) have their non-wildcard
      segments encoded independently so substring filter semantics are
      preserved — only the literal ``*`` characters are never hex-encoded.
    """
    if not value or _ESCAPE_RE.search(value):
        return value

    if "*" in value:
        # Encode each segment between wildcards; '*' characters stay as-is
        return "*".join(_encode_literal(seg) for seg in value.split("*"))

    return _encode_literal(value)


def _case_randomize(s: str) -> str:
    """Return *s* with each character randomly uppercased or lowercased."""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def _obfuscate_attribute(attr: str) -> str:
    """
    Obfuscate an attribute name by either:

    * Replacing it with its numeric OID (~35 % of the time, when a mapping
      exists), or
    * Randomising its character case.
    """
    oid = _ATTR_OIDS.get(attr.lower())
    if oid and random.random() < 0.35:
        return oid
    return _case_randomize(attr)


# ---------------------------------------------------------------------------
# Structural transformation helpers
# ---------------------------------------------------------------------------

def _double_negation(node: ASTNode) -> ASTNode:
    """Return ``!!node`` — semantically a no-op for any filter."""
    return ASTNode(
        type=NodeType.NOT,
        children=[ASTNode(type=NodeType.NOT, children=[node])],
    )


def _redundant_and(node: ASTNode) -> ASTNode:
    """
    Return ``(&(attr op val)(attr=*))`` which is logically equivalent to
    ``(attr op val)`` because the presence assertion is always implied.

    The attribute in the injected PRESENT child is independently
    case-randomised so the two sub-filters are visually distinct.
    """
    present = ASTNode(
        type=NodeType.PRESENT,
        attribute=_case_randomize(node.attribute or ""),
    )
    children = [node, present]
    random.shuffle(children)
    return ASTNode(type=NodeType.AND, children=children)


def _single_wrapper(node: ASTNode) -> ASTNode:
    """
    Return ``(&(filter))`` or ``(|(filter))``.

    A single-child AND/OR is equivalent to its sole child under RFC 4511,
    but the extra layer of nesting adds visual noise.
    """
    wtype = random.choice((NodeType.AND, NodeType.OR))
    return ASTNode(type=wtype, children=[node])


# ---------------------------------------------------------------------------
# Core recursive transformation
# ---------------------------------------------------------------------------

def _transform(node: ASTNode, depth: int = 0) -> ASTNode:
    """
    Recursively apply lexical and structural obfuscation to *node*.

    Returns a **new** ``ASTNode`` tree; the original is never mutated.

    Lexical transformations (applied at every node):
        * Attribute names are mixed-cased or replaced with numeric OIDs.
        * Assertion values are hex-encoded: fully, partially, or scattered.
        * Hex digits themselves are randomly uppercased or lowercased.

    Structural transformations (probabilistic):
        * AND / OR children are shuffled.
        * A random child of AND / OR may be wrapped in ``!!``  (30 %).
        * FILTER leaves may be wrapped in ``!!``  (15 %),
          turned into a redundant ``(&(f)(attr=*))``  (15 %),
          or enclosed in a single-child AND / OR at root level  (10 %).
    """
    # Recurse first so children are already transformed
    new_children = [_transform(c, depth + 1) for c in node.children]

    # Build a fresh node — avoids mutating the caller's AST
    n = ASTNode(
        type=node.type,
        children=new_children,
        attribute=node.attribute,
        operator=node.operator,
        value=node.value,
    )

    # -- Lexical obfuscation ------------------------------------------------
    if n.attribute is not None:
        n.attribute = _obfuscate_attribute(n.attribute)

    if n.type == NodeType.FILTER and n.value is not None:
        n.value = _obfuscate_value(n.value)

    # -- Structural obfuscation: compound nodes -----------------------------
    if n.type in (NodeType.AND, NodeType.OR):
        random.shuffle(n.children)

        # Wrap one random child in double-negation (30 % chance)
        if n.children and random.random() < 0.30:
            idx = random.randrange(len(n.children))
            n.children[idx] = _double_negation(n.children[idx])

    # -- Structural obfuscation: leaf FILTER nodes --------------------------
    elif n.type == NodeType.FILTER:
        roll = random.random()
        if roll < 0.15:
            # !!(...) wrapper
            n = _double_negation(n)
        elif roll < 0.30 and n.operator == "=":
            # Inject a redundant presence assertion: (&(attr=val)(attr=*))
            n = _redundant_and(n)
        elif roll < 0.40 and depth == 0:
            # Wrap a top-level simple filter in a single-element AND or OR
            n = _single_wrapper(n)

    return n


# ---------------------------------------------------------------------------
# Serialiser
# ---------------------------------------------------------------------------

def serialize(node: ASTNode) -> str:
    """Render *node* back to an LDAP filter string."""
    match node.type:
        case NodeType.AND:
            return "(&" + "".join(serialize(c) for c in node.children) + ")"
        case NodeType.OR:
            return "(|" + "".join(serialize(c) for c in node.children) + ")"
        case NodeType.NOT:
            return "(!" + serialize(node.children[0]) + ")"
        case NodeType.PRESENT:
            return f"({node.attribute}=*)"
        case NodeType.FILTER:
            return f"({node.attribute}{node.operator}{node.value})"
        case _:
            raise LDAPParseError(f"Unknown node type: {node.type!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def obfuscate(query: str, seed: Optional[int] = None) -> str:
    """
    Parse *query* and return a semantically equivalent, obfuscated filter.

    Parameters
    ----------
    query:
        A valid LDAP filter string (RFC 4515).
    seed:
        Optional integer seed for reproducible output.

    Returns
    -------
    str
        An obfuscated LDAP filter semantically equivalent to *query*.

    Raises
    ------
    LDAPParseError
        If *query* is not a valid LDAP filter.

    Examples
    --------
    Illustrative outputs (exact result depends on the random seed):

        obfuscate("(uid=jdoe)", seed=42)
        # → '(uId=\\6a\\64\\6f\\65)'

        obfuscate("(&(uid=admin)(objectClass=person))")
        # → '(&(2.5.4.0=\\70\\65\\72\\73\\6F\\6e)((!(!( uId=\\61\\64\\6d\\69\\6e))))'
    """
    if seed is not None:
        random.seed(seed)
    ast = LDAPParser(query).parse()
    ast = _transform(ast)
    return serialize(ast)


def parse(query: str) -> ASTNode:
    """
    Parse *query* and return the corresponding :class:`ASTNode` tree.

    Parameters
    ----------
    query:
        A valid LDAP filter string (RFC 4515).

    Returns
    -------
    ASTNode
        Root node of the abstract syntax tree.

    Raises
    ------
    LDAPParseError
        If *query* is not a valid LDAP filter.
    """
    return LDAPParser(query).parse()
