#!/usr/bin/env python3
"""Check the D2Vita contract v1 schemas.

    python3 contract/tools/check_schemas.py

Needs the `jsonschema` package. When it is missing and contract/.venv exists,
the script re-runs itself with the venv interpreter (see contract/README.md).
"""
import functools
import json
import os
import re
import sys
from pathlib import Path

CONTRACT_DIR = Path(__file__).resolve().parent.parent
SCHEMA_DIR = CONTRACT_DIR / "schemas"
VENV_DIR = CONTRACT_DIR / ".venv"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
ID_PREFIX = "https://raw.githubusercontent.com/Franckrst/D2Vita-website/main/contract/schemas/"
VENV_HINT = (
    "the jsonschema package is missing: run `make -C contract venv` "
    "(or see contract/README.md), then retry"
)


# --------------------------------------------------------------------------
# Schema loading and validation
# --------------------------------------------------------------------------

def json_pointer(path):
    """RFC 6901 pointer for a jsonschema error path ("" is the document root)."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in path)


@functools.lru_cache(maxsize=None)
def _load_schemas_cached(schema_dir):
    schemas = {}
    for path in sorted(Path(schema_dir).glob("*.schema.json")):
        schemas[path.name[: -len(".schema.json")]] = json.loads(path.read_text("utf-8"))
    return schemas


def load_schemas(schema_dir=SCHEMA_DIR):
    """Schemas keyed by file stem, e.g. "claim.v1"."""
    return _load_schemas_cached(str(schema_dir))


def python_pattern(pattern):
    """Translate an anchored ECMA-262 pattern for Python's re.search.

    In Python, `$` also matches just before a trailing newline, so
    "abc\\n" would match "^abc$". ECMA-262 (ajv) does not accept it.
    Contract patterns always end with the `$` anchor (see
    pattern_portability_problems), which becomes `\\Z` here.
    """
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        return pattern[:-1] + r"\Z"
    return pattern


def _import_jsonschema():
    try:
        import jsonschema
        import referencing
        import referencing.jsonschema
    except ImportError as exc:  # pragma: no cover - environment problem
        raise SystemExit(VENV_HINT) from exc
    return jsonschema, referencing


@functools.lru_cache(maxsize=None)
def _validator_class():
    jsonschema, _ = _import_jsonschema()

    def ecma_pattern(validator, pattern, instance, schema):
        if validator.is_type(instance, "string") and not re.search(python_pattern(pattern), instance):
            yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")

    return jsonschema.validators.extend(jsonschema.Draft202012Validator, {"pattern": ecma_pattern})


@functools.lru_cache(maxsize=None)
def _registry(schema_dir=str(SCHEMA_DIR)):
    _, referencing = _import_jsonschema()
    resources = []
    for schema in load_schemas(schema_dir).values():
        # Registered without "$schema": when a $ref lands on a document root,
        # jsonschema picks the validator class from "$schema" and would drop
        # the ECMA-262 pattern semantics of _validator_class(). The dialect
        # is pinned explicitly instead.
        contents = {key: value for key, value in schema.items() if key != "$schema"}
        resources.append(
            (schema["$id"], referencing.Resource(contents, referencing.jsonschema.DRAFT202012))
        )
    return referencing.Registry().with_resources(resources)


def schema_errors(schema_name, instance, definition=None):
    """Validation errors of `instance` against a schema or one of its $defs."""
    schema_id = load_schemas()[schema_name]["$id"]
    ref = schema_id + (f"#/$defs/{definition}" if definition else "")
    validator = _validator_class()({"$ref": ref}, registry=_registry())
    return sorted(validator.iter_errors(instance), key=lambda e: json_pointer(e.absolute_path))


def _walk(node, where=""):
    """Yield (json pointer, dict) for every object inside a schema document."""
    if isinstance(node, dict):
        yield where, node
        for key, value in node.items():
            yield from _walk(value, f"{where}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{where}/{index}")


def iter_patterns():
    """Yield ("<schema>#<pointer>", pattern) for every pattern keyword."""
    for name, schema in load_schemas().items():
        for where, node in _walk(schema):
            if isinstance(node.get("pattern"), str):
                yield f"{name}#{where}", node["pattern"]


def pattern_portability_problems(pattern):
    """Reasons why a pattern could behave differently in ECMA-262 and Python."""
    problems = []
    if not pattern.startswith("^"):
        problems.append("must start with the ^ anchor")
    if not pattern.endswith("$") or pattern.endswith("\\$"):
        problems.append("must end with an unescaped $ anchor")
    if any(ord(ch) > 127 for ch in pattern):
        problems.append("non-ASCII character (use \\uXXXX)")
    in_class = False
    index = 0
    while index < len(pattern):
        ch = pattern[index]
        if ch == "\\":
            escaped = pattern[index + 1 : index + 2]
            if escaped in ("d", "D", "w", "W", "s", "S", "b", "B"):
                problems.append(f"\\{escaped} differs between engines, use an explicit class")
            index += 2
            continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == ".":
            problems.append(". outside a class differs between engines (newlines)")
        elif ch == "$" and index != len(pattern) - 1:
            problems.append("$ is only allowed as the final anchor")
        elif ch == "^" and index != 0:
            problems.append("^ is only allowed as the leading anchor")
        index += 1
    return problems


def check_schema_documents():
    """Raise if a schema document is not a sound 2020-12 contract schema."""
    jsonschema, _ = _import_jsonschema()
    registry = _registry()
    for name, schema in load_schemas().items():
        if schema.get("$schema") != DIALECT:
            raise ValueError(f"{name}: $schema must be {DIALECT}")
        if schema.get("$id") != f"{ID_PREFIX}{name}.schema.json":
            raise ValueError(f"{name}: unexpected $id {schema.get('$id')!r}")
        jsonschema.Draft202012Validator.check_schema(schema)
        resolver = registry.resolver(base_uri=schema["$id"])
        for where, node in _walk(schema):
            if isinstance(node.get("$ref"), str):
                resolver.lookup(node["$ref"])  # raises Unresolvable
    for where, pattern in iter_patterns():
        problems = pattern_portability_problems(pattern)
        if problems:
            raise ValueError(f"{where}: {pattern!r}: {'; '.join(problems)}")


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def _ensure_jsonschema():
    try:
        import jsonschema  # noqa: F401
        return
    except ImportError:
        pass
    venv_python = VENV_DIR / "bin" / "python"
    if venv_python.exists() and Path(sys.prefix).resolve() != VENV_DIR.resolve():
        os.execv(str(venv_python), [str(venv_python), str(Path(__file__).resolve()), *sys.argv[1:]])
    raise SystemExit(VENV_HINT)


def main():
    _ensure_jsonschema()
    check_schema_documents()
    print(f"OK: {len(load_schemas())} schemas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
