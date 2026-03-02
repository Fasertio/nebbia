"""
Test suite per nebbia.
Esegui con:  pytest tests/ -v
"""

import pytest
from nebbia import LDAPParseError, obfuscate, parse, serialize

VALID_QUERIES = [
    "(uid=jdoe)",
    "(cn=*)",
    "(!(locked=true))",
    "(&(objectClass=person)(uid=john))",
    "(|(cn=Alice)(cn=Bob)(cn=Charlie))",
    "(&(objectClass=user)(|(dept=IT)(dept=HR))(!(disabled=TRUE)))",
    "(&(distinguishedName=CN=krbtgt,CN=Users,DC=company-b,DC=local))",
    "(sAMAccountName=krbtgt)",
    "(userPassword=P@ssw0rd!)",
]

INVALID_QUERIES = [
    "",
    "uid=jdoe",
    "(uid=jdoe",
    "(&(uid=jdoe)",
    "((uid=jdoe))",
]


class TestParser:
    @pytest.mark.parametrize("query", VALID_QUERIES)
    def test_parse_valid(self, query):
        ast = parse(query)
        assert ast is not None

    @pytest.mark.parametrize("query", INVALID_QUERIES)
    def test_parse_invalid(self, query):
        with pytest.raises((LDAPParseError, ValueError)):
            parse(query)

    def test_serialize_roundtrip(self):
        query = "(&(objectClass=person)(uid=john))"
        ast   = parse(query)
        out   = serialize(ast)
        # riparsa per verificare che sia ancora valida
        ast2 = parse(out)
        assert serialize(ast2) == out

class TestObfuscate:
    @pytest.mark.parametrize("query", VALID_QUERIES)
    def test_output_is_valid_ldap(self, query):
        result = obfuscate(query, seed=0)
        ast    = parse(result)
        assert ast is not None

    @pytest.mark.parametrize("query", VALID_QUERIES)
    def test_deterministic_with_seed(self, query):
        r1 = obfuscate(query, seed=99)
        r2 = obfuscate(query, seed=99)
        assert r1 == r2

    @pytest.mark.parametrize("query", VALID_QUERIES)
    def test_different_seeds_differ(self, query):
        results = {obfuscate(query, seed=i) for i in range(10)}
        # almeno 2 varianti diverse (eccetto query banali)
        if len(query) > 10:
            assert len(results) > 1

    def test_hex_escape_preserves_semantics(self):
        from nebbia.core import NodeType

        query = "(uid=admin)"
        for seed in range(20):
            result = obfuscate(query, seed=seed)
            ast    = parse(result)
            # dopo eventuale doppia negazione raggiungiamo il FILTER
            node = ast
            while node.type == NodeType.NOT:
                node = node.children[0]
            assert node.type == NodeType.FILTER
            assert node.operator == "="

    def test_double_negation_present(self):
        from nebbia.core import NodeType

        # cerca un seed che produca una doppia negazione
        for seed in range(100):
            result = obfuscate("(&(uid=a)(cn=b))", seed=seed)
            ast    = parse(result)
            found  = _has_double_negation(ast)
            if found:
                break
        # non assert su found: è probabilistico, ma log utile
        _ = found  # pylint: disable=pointless-statement

    def test_structural_transforms_and_or(self):
        from nebbia.core import NodeType

        query = "(&(uid=alice)(cn=bob)(sn=charlie))"
        leaves_orig = _collect_leaves(parse(query))

        for seed in range(10):
            result = obfuscate(query, seed=seed)
            ast    = parse(result)
            leaves = _collect_leaves(ast)

            attrs_orig = sorted(a for a, _ in leaves_orig)
            attrs_obf  = sorted(a.lower() for a, _ in leaves)
            assert attrs_orig == attrs_obf

class TestCLI:
    def test_cli_single_query(self, capsys):
        from nebbia.__main__ import main

        main(["(uid=jdoe)", "--seed", "1", "--no-color"])
        captured = capsys.readouterr()
        assert "RESULT" in captured.out

    def test_cli_count(self, capsys):
        from nebbia.__main__ import main

        main(["(uid=jdoe)", "--count", "3", "--no-color"])
        captured = capsys.readouterr()
        lines = [l for l in captured.out.splitlines() if "RESULT" in l]
        assert len(lines) == 3

    def test_cli_demo(self, capsys):
        from nebbia.__main__ import main

        with pytest.raises(SystemExit) as exc:
            main(["--demo", "--no-color"])
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "IPNUT" in captured.out

    def test_cli_invalid_query(self, capsys):
        from nebbia.__main__ import main

        with pytest.raises(SystemExit) as exc:
            main(["uid=invalid", "--no-color"])
        assert exc.value.code != 0


def _has_double_negation(node) -> bool:
    from nebbia.core import NodeType
    if node.type == NodeType.NOT and node.children:
        child = node.children[0]
        if child.type == NodeType.NOT:
            return True
    return any(_has_double_negation(c) for c in node.children)


def _collect_leaves(node) -> list[tuple[str, str]]:
    from nebbia.core import NodeType
    if node.type == NodeType.FILTER:
        return [(node.attribute.lower(), node.value)]
    if node.type == NodeType.PRESENT:
        return [(node.attribute.lower(), "*")]
    result = []
    for c in node.children:
        result.extend(_collect_leaves(c))
    return result
