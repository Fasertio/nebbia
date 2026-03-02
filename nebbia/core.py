"""
nebbia.core
"""

from __future__ import annotations

import re
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


#AST Node
class NodeType(Enum):
    AND     = auto()
    OR      = auto()
    NOT     = auto()
    FILTER  = auto()   # (attr op value)
    PRESENT = auto()   # (attr=*)


@dataclass
class ASTNode:
    type: NodeType
    children: list[ASTNode] = field(default_factory=list)
    attribute: Optional[str] = None
    operator:  Optional[str] = None
    value:     Optional[str] = None

    def __repr__(self) -> str:
        if self.type == NodeType.FILTER:
            return f"ASTNode(FILTER, {self.attribute!r}{self.operator}{self.value!r})"
        if self.type == NodeType.PRESENT:
            return f"ASTNode(PRESENT, {self.attribute!r}=*)"
        return f"ASTNode({self.type.name}, children={len(self.children)})"


#Parser

class LDAPParseError(ValueError):
    """Malformed LDAP query"""


class LDAPParser:
    """LDAP Parser"""

    def __init__(self, query: str) -> None:
        self.src = query.strip()
        self.pos = 0

    def _peek(self) -> str:
        return self.src[self.pos] if self.pos < len(self.src) else ""

    def _consume(self, ch: str) -> None:
        if self.pos >= len(self.src):
            raise LDAPParseError(
                f"Unexpected line end '{ch}'"
            )
        if self.src[self.pos] != ch:
            ctx = self.src[max(0, self.pos - 5): self.pos + 5]
            raise LDAPParseError(
                f"Expected '{ch}', found '{self.src[self.pos]}' "
                f"at pos {self.pos} (context: '...{ctx}...')"
            )
        self.pos += 1


    def parse(self) -> ASTNode:
        node = self._parse_filter()
        if self.pos != len(self.src):
            raise LDAPParseError(
                f"Input not used at pos {self.pos}: '{self.src[self.pos:]}'"
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
        self.pos += 1
        node = ASTNode(type=ntype)
        while self._peek() == "(":
            node.children.append(self._parse_filter())
        return node

    def _parse_not(self) -> ASTNode:
        self.pos += 1
        node = ASTNode(type=NodeType.NOT)
        node.children.append(self._parse_filter())
        return node

    def _parse_simple(self) -> ASTNode:
        try:
            end = self.src.index(")", self.pos)
        except ValueError:
            raise LDAPParseError("Expected ')'")

        expr = self.src[self.pos:end]
        self.pos = end

        m = re.match(r"^([^=<>~!]+)=\*$", expr)
        if m:
            return ASTNode(type=NodeType.PRESENT, attribute=m.group(1))

        m = re.match(r"^([^=<>~!]+)(>=|<=|~=|=)(.*)$", expr)
        if m:
            return ASTNode(
                type=NodeType.FILTER,
                attribute=m.group(1),
                operator=m.group(2),
                value=m.group(3),
            )

        raise LDAPParseError(f"Simple filter not recognized: '{expr}'")


def _case_randomize(s: str) -> str:
    """Random mixed-case"""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def _hex_encode_full(value: str) -> str:
    """LDAP escape \\HH."""
    return "".join(f"\\{ord(c):02X}" for c in value)


def _hex_encode_partial(value: str) -> str:
    """Alphanumeric encoding"""
    return "".join(
        f"\\{ord(c):02X}" if c.isalnum() and random.random() > 0.4 else c
        for c in value
    )


def _obfuscate_value(value: str) -> str:
    strategy = random.choice(["plain", "full_hex", "partial_hex"])
    if strategy == "full_hex":
        return _hex_encode_full(value)
    if strategy == "partial_hex":
        return _hex_encode_partial(value)
    return value


def _double_negation(node: ASTNode) -> ASTNode:
    return ASTNode(
        type=NodeType.NOT,
        children=[ASTNode(type=NodeType.NOT, children=[node])],
    )


def _shuffle_children(node: ASTNode) -> ASTNode:
    """AND/OR child mix"""
    if node.type in (NodeType.AND, NodeType.OR) and node.children:
        random.shuffle(node.children)
    return node


def _transform(node: ASTNode, depth: int = 0) -> ASTNode:
    """Recursive transformation"""

    # ricorsione sui figli
    node.children = [_transform(c, depth + 1) for c in node.children]

    # ── offuscamento lessicale ───────────────
    if node.attribute:
        node.attribute = _case_randomize(node.attribute)

    if node.type == NodeType.FILTER and node.value is not None:
        node.value = _obfuscate_value(node.value)

    # ── trasformazioni strutturali ───────────
    if node.type in (NodeType.AND, NodeType.OR):
        node = _shuffle_children(node)
        # doppia negazione su un figlio casuale con prob 30 %
        if node.children and random.random() < 0.30:
            idx = random.randrange(len(node.children))
            node.children[idx] = _double_negation(node.children[idx])

    elif node.type == NodeType.FILTER and depth > 0 and random.random() < 0.20:
        node = _double_negation(node)

    return node


def serialize(node: ASTNode) -> str:
    """ASTNode conversion"""
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
            raise LDAPParseError(f"Unknown node: {node.type}")


#public function
def obfuscate(query: str, seed: Optional[int] = None) -> str:
    """
    Parameters
    ----------
    query : str
    seed : int, optional

    Returns
    -------
    str

    Raises
    ------
    LDAPParseError

    Examples
    --------
    >>> from nebbia import obfuscate
    >>> obfuscate("(uid=jdoe)", seed=42)
    '(uId=\\\\6A\\\\64\\\\6F\\\\65)'
    """
    if seed is not None:
        random.seed(seed)
    ast = LDAPParser(query).parse()
    ast = _transform(ast)
    return serialize(ast)


def parse(query: str) -> ASTNode:
    """
    Parameters
    ----------
    query : str

    Returns
    -------
    ASTNode
    """
    return LDAPParser(query).parse()
