# nebbia

LDAP filter obfuscation tool.  
Analyze the filter using **Abstract Syntax Tree**, applies structural transformation and return an equivalent query.
Useful for sneaky query to the Domain Controller or edit tools that queries against the domain (like Certipy).

---

## Installation

```bash
pip install nebbia
```

dev:

```bash
git clone https://github.com/Fasertio/nebbia
cd nebbia
pip install -e ".[dev]"
```

---

## Library usage

```python
from nebbia import obfuscate, parse, serialize

query  = "(&(objectClass=person)(uid=jdoe)(!(locked=true)))"
result = obfuscate(query)
print(result)
# es: (&((!(!(\75Id=\6A\64\6F\65))))(oBjEcTcLaSs=\70\65\72son)(!(loCkeD=true)))

r1 = obfuscate(query, seed=42)
r2 = obfuscate(query, seed=42)
assert r1 == r2

from nebbia import parse, serialize, NodeType

ast = parse("(sAMAccountName=krbtgt)")
print(ast)
# ASTNode(FILTER, 'sAMAccountName'='krbtgt')

ast.value = "administrator"
print(serialize(ast))
# (sAMAccountName=administrator)
```

---

## CLI

```bash

#single query
nebbia "(uid=jdoe)"

#multiple
nebbia "(&(uid=admin)(objectClass=person))" --count 3

#deterministic output
nebbia "(cn=krbtgt)" --seed 42

#disable ANSI color
nebbia "(uid=test)" --no-color

#stdin
echo "(uid=admin)" | nebbia

#python module
python -m nebbia "(uid=jdoe)" --count 2
```

---

## License

MIT
