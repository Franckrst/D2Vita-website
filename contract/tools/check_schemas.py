#!/usr/bin/env python3
"""Check the D2Vita contract v1 schemas and signature vectors.

    python3 contract/tools/check_schemas.py

This file is also the reference implementation of the signature rules
(contract/signature-rules.v1.md): canon(), signature_id(). That part only
needs the standard library, so gen_vectors.py can import it anywhere.

Validation needs the `jsonschema` package. When it is missing and
contract/.venv exists, the script re-runs itself with the venv interpreter
(see contract/README.md).
"""
import base64
import functools
import hashlib
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
# Signature rules v1 (reference implementation of signature-rules.v1.md)
# --------------------------------------------------------------------------

RULES_VERSION = 1

# (selector, template). The selector is the claim kind, followed by
# "/<features.pc.region>" for host_fault. signature-rules.v1.md reproduces
# this table verbatim (checked by the test suite).
SIGNATURE_TEMPLATES = (
    ("halt", "halt|{features.code}|{features.location}|{features.frames:3}"),
    ("guest_fault", "gfault|{features.exception}|{features.eip}|{features.frames:2}"),
    ("host_fault/jit", "hfault_jit|{features.stop_reason}|{features.guest_frames:3}"),
    ("host_fault/eboot", "hfault|{build_id}|{features.pc.offset}|{features.lr.offset}"),
    ("host_fault/sysmodule", "hfault_sys|{features.pc.module}|{features.pc.offset}"),
    ("host_fault/unknown", "hfault_unknown|{build_id}|{features.pc.offset}|{features.lr.offset}"),
    ("abnormal_exit", "exit|{features.reason}|{features.import ?? features.code}|{features.frames:1}"),
    ("hang", "hang|{features.eip}"),
)

ABSENT = "-"
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
_PATH = r"[a-z_]+(?:\.[a-z_]+)*"
_LIST_EXPRESSION = re.compile(rf"\A({_PATH}):([1-9][0-9]*)\Z")
_PATH_EXPRESSION = re.compile(rf"\A{_PATH}\Z")


def _lookup(document, path):
    value = document
    for key in path.split("."):
        if not isinstance(value, dict):
            raise TypeError(f"{path}: {key!r} is looked up in a non-object")
        value = value[key]  # KeyError when absent: templates only name required fields
    return value


def _format_scalar(value, path):
    if value is None:
        return ABSENT
    if isinstance(value, bool):
        raise TypeError(f"{path}: booleans are not used by templates")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # JSON 1420.0 and 1.42e3 are the integer 1420 (JSON Schema "integer").
        if not value.is_integer():
            raise ValueError(f"{path}: {value!r} is not an integer")
        return str(int(value))
    if isinstance(value, str):
        return value
    raise TypeError(f"{path}: {type(value).__name__} is not a scalar")


def _expand(expression, document):
    list_match = _LIST_EXPRESSION.match(expression)
    if list_match:
        path, count = list_match.group(1), int(list_match.group(2))
        items = _lookup(document, path)
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise TypeError(f"{path}: expected an array of strings")
        return ",".join(items[:count]) if items else ABSENT
    alternatives = [part.strip() for part in expression.split("??")]
    if not all(_PATH_EXPRESSION.match(path) for path in alternatives):
        raise ValueError(f"malformed placeholder {{{expression}}}")
    for path in alternatives:
        value = _lookup(document, path)
        if isinstance(value, (dict, list)):
            raise TypeError(f"{path}: expected a scalar")
        if value is not None:
            return _format_scalar(value, path)
    return ABSENT


def render_template(template, document):
    """Expand every {placeholder} of a signature template."""
    return _PLACEHOLDER.sub(lambda match: _expand(match.group(1), document), template)


def template_for(claim):
    selector = claim.get("kind")
    if selector == "host_fault":
        selector = f"host_fault/{claim['features']['pc']['region']}"
    for candidate, template in SIGNATURE_TEMPLATES:
        if candidate == selector:
            return template
    raise ValueError(f"no signature template for {selector!r}")


def canon(claim):
    """Canonical string of a claim that is valid against claim.v1.schema.json."""
    return render_template(template_for(claim), claim)


def signature_id(canon_string):
    """"S" + base32(sha256(utf8(canon)))[0:15], RFC 4648 alphabet, no padding."""
    digest = hashlib.sha256(canon_string.encode("utf-8")).digest()
    return "S" + base64.b32encode(digest).decode("ascii")[:15]


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
