#!/usr/bin/env python3
"""Generate the contract test vectors, deterministically.

    python3 contract/tools/gen_vectors.py            # write contract/vectors/*.json
    python3 contract/tools/gen_vectors.py --check    # exit 1 if a file differs

Every key, nonce and identifier is fixed in this file, so two runs produce
the same bytes. --check regenerates in memory and compares byte for byte.
Needs only the standard library and PyNaCl (no jsonschema).
"""
import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

import check_schemas

VECTOR_DIR = check_schemas.VECTOR_DIR


class GenerationError(Exception):
    """The generator's own cross-checks failed; nothing is written."""


def dump(document):
    """The exact text of a vector file."""
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


# --------------------------------------------------------------------------
# Deterministic identifiers and sizes
# --------------------------------------------------------------------------

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
BASE_UNIX = 1789284000
BUILD = "0.1.0+ab12cd34ef56"
OTHER_BUILD = "0.1.1+0123456789ab-dirty"


def label_digest(label):
    return hashlib.sha256(("d2vita-contract-vectors:" + label).encode("ascii")).digest()


def ulid(index):
    """A fixed ULID for vector number `index` (vectors only, never random)."""
    value = ((BASE_UNIX * 1000 + index) << 80) | int.from_bytes(label_digest(f"report-{index}")[:10], "big")
    return "".join(CROCKFORD[(value >> (5 * (25 - position))) & 31] for position in range(26))


def install_id(index):
    return label_digest(f"install-{index}").hex()[:32]


def sealed_size(plaintext_bytes, chunk_size=65536):
    """Size of a D2VSEAL1 object (sealed-format.md): header, data, one tag per chunk."""
    return 72 + plaintext_bytes + 16 * (plaintext_bytes // chunk_size + 1)


def offers(*plaintext_sizes):
    return [{"name": name, "bytes": sealed_size(size)} for name, size in plaintext_sizes]


# --------------------------------------------------------------------------
# Signature vectors
# --------------------------------------------------------------------------

SPEC_EXAMPLE_CLAIM = {
    "v": 1,
    "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD",
    "install_id": "4f3c9a0e8b7d6c5a4f3e2d1c0b9a8f7e",
    "build_id": "0.1.0+ab12cd34ef56",
    "channel": "release",
    "platform": {"model": "vita", "fw": "3.65"},
    "session": {"started_unix": 1789284000, "uptime_s": 967, "online": False},
    "kind": "halt",
    "features": {
        "code": 1420,
        "location": None,
        "frames": ["Game+0x1fedf4", "Game+0x451c23", "Game+0x44f570"],
    },
    "hints": ["guest_fault"],
    "artifacts": [
        {"name": "crash_txt", "bytes": 2210},
        {"name": "crash_log", "bytes": 3104},
        {"name": "boot_progress", "bytes": 262144},
    ],
}

LOGS = (("crash_log", 3016), ("boot_progress", 278528))


def claim(index, kind, features, artifacts, hints=(), build_id=BUILD, channel="release",
          model="vita", fw="3.65", online=False, uptime_s=900):
    return {
        "v": 1,
        "report_id": ulid(index),
        "install_id": install_id(index),
        "build_id": build_id,
        "channel": channel,
        "platform": {"model": model, "fw": fw},
        "session": {"started_unix": BASE_UNIX + 3600 * index, "uptime_s": uptime_s, "online": online},
        "kind": kind,
        "features": features,
        "hints": list(hints),
        "artifacts": artifacts,
    }


def frames(*offsets):
    return ["Game+0x%x" % offset for offset in offsets]


def host(region, module, offset):
    return {"region": region, "module": module, "offset": "0x%x" % offset}


HALT_ARTIFACTS = offers(("crash_txt", 2122), *LOGS)
EXIT_ARTIFACTS = offers(("crash_txt", 1830), *LOGS)
LOG_ARTIFACTS = offers(*LOGS)
DUMP_ARTIFACTS = offers(("dump", 1466000), *LOGS)
SIXTEEN = tuple(0x1fe000 + 0x40 * i for i in range(16))

# (name, claim, canon written by hand from signature-rules.v1.md)
SIGNATURE_CASES = [
    ("spec_example_halt", SPEC_EXAMPLE_CLAIM,
     "halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570"),
    ("halt_location_five_frames",
     claim(1, "halt", {"code": 904, "location": "Codec.cpp:1377",
                       "frames": frames(0x1f1a2c, 0x1f0f30, 0x2a1b40, 0x451c23, 0x44f570)},
           HALT_ARTIFACTS, hints=["guest_fault", "hang"]),
     "halt|904|Codec.cpp:1377|Game+0x1f1a2c,Game+0x1f0f30,Game+0x2a1b40"),
    ("halt_one_frame",
     claim(2, "halt", {"code": 316, "location": None, "frames": frames(0x65420)}, HALT_ARTIFACTS),
     "halt|316|-|Game+0x65420"),
    ("halt_no_frames",
     claim(3, "halt", {"code": 1632, "location": "Codec.cpp:1234", "frames": []}, HALT_ARTIFACTS,
           online=True),
     "halt|1632|Codec.cpp:1234|-"),
    ("halt_code_written_as_float",
     claim(4, "halt", {"code": 1420.0, "location": None, "frames": frames(0x1fedf4)}, HALT_ARTIFACTS),
     "halt|1420|-|Game+0x1fedf4"),
    ("halt_sixteen_frames",
     claim(5, "halt", {"code": 452, "location": None, "frames": frames(*SIXTEEN)}, HALT_ARTIFACTS),
     "halt|452|-|Game+0x1fe000,Game+0x1fe040,Game+0x1fe080"),
    ("guest_fault_worker_four_frames",
     claim(6, "guest_fault", {"exception": "0xc0000005", "thread": "worker", "eip": "Game+0x2b1c40",
                              "frames": frames(0x2b1c40, 0x2b0e18, 0x1d2f00, 0x10a0c4)}, LOG_ARTIFACTS),
     "gfault|0xc0000005|Game+0x2b1c40|Game+0x2b1c40,Game+0x2b0e18"),
    ("guest_fault_main_one_frame",
     claim(7, "guest_fault", {"exception": "0xc0000094", "thread": "main", "eip": "Game+0x12f3a8",
                              "frames": frames(0x12f3a8)}, LOG_ARTIFACTS, hints=["hang"]),
     "gfault|0xc0000094|Game+0x12f3a8|Game+0x12f3a8"),
    ("guest_fault_unknown_exception_no_frames",
     claim(8, "guest_fault", {"exception": None, "thread": "worker", "eip": "Game+0x0", "frames": []},
           LOG_ARTIFACTS),
     "gfault|-|Game+0x0|-"),
    ("host_fault_jit",
     claim(9, "host_fault", {"stop_reason": "0x30004", "thread_name": "d2vita_main",
                             "pc": host("jit", "jit", 0x2c4184), "lr": host("unknown", "unknown", 0x1),
                             "guest_frames": frames(0x1fedf4, 0x451c23, 0x44f570, 0x10a0c4, 0x1000),
                             "redaction": "clean"},
           DUMP_ARTIFACTS, hints=["halt", "guest_fault"]),
     "hfault_jit|0x30004|Game+0x1fedf4,Game+0x451c23,Game+0x44f570"),
    ("host_fault_jit_no_guest_frames",
     claim(10, "host_fault", {"stop_reason": None, "thread_name": None,
                              "pc": host("jit", "jit", 0x1c), "lr": host("jit", "jit", 0x8),
                              "guest_frames": [], "redaction": "clean"}, DUMP_ARTIFACTS),
     "hfault_jit|-|-"),
    ("host_fault_eboot",
     claim(11, "host_fault", {"stop_reason": "0x30004", "thread_name": "d2cr_upload",
                              "pc": host("eboot", "eboot", 0x2c4184), "lr": host("eboot", "eboot", 0x2c3f10),
                              "guest_frames": frames(0x1fedf4, 0x451c23), "redaction": "clean"},
           DUMP_ARTIFACTS),
     "hfault|0.1.0+ab12cd34ef56|0x2c4184|0x2c3f10"),
    ("host_fault_eboot_other_build",
     claim(12, "host_fault", {"stop_reason": "0x30004", "thread_name": "d2cr_upload",
                              "pc": host("eboot", "eboot", 0x2c4184), "lr": host("eboot", "eboot", 0x2c3f10),
                              "guest_frames": frames(0x1fedf4, 0x451c23), "redaction": "clean"},
           DUMP_ARTIFACTS, build_id=OTHER_BUILD, channel="dev"),
     "hfault|0.1.1+0123456789ab-dirty|0x2c4184|0x2c3f10"),
    ("host_fault_sysmodule",
     claim(13, "host_fault", {"stop_reason": "0x30002", "thread_name": "SceGxmDisplayQueue",
                              "pc": host("sysmodule", "SceLibKernel", 0x1f2c),
                              "lr": host("eboot", "eboot", 0x10a0c4),
                              "guest_frames": frames(0x2b1c40), "redaction": "clean"}, DUMP_ARTIFACTS),
     "hfault_sys|SceLibKernel|0x1f2c"),
    ("host_fault_sysmodule_other_build",
     claim(14, "host_fault", {"stop_reason": "0x30002", "thread_name": "SceGxmDisplayQueue",
                              "pc": host("sysmodule", "SceLibKernel", 0x1f2c),
                              "lr": host("eboot", "eboot", 0x10b000),
                              "guest_frames": [], "redaction": "clean"},
           DUMP_ARTIFACTS, build_id=OTHER_BUILD, channel="dev", model="pstv", fw="3.74"),
     "hfault_sys|SceLibKernel|0x1f2c"),
    ("host_fault_unknown_region",
     claim(15, "host_fault", {"stop_reason": "0x30003", "thread_name": "d2vita_main",
                              "pc": host("unknown", "unknown", 0x0), "lr": host("eboot", "eboot", 0x10a0c4),
                              "guest_frames": frames(0x1fedf4), "redaction": "clean"}, DUMP_ARTIFACTS),
     "hfault_unknown|0.1.0+ab12cd34ef56|0x0|0x10a0c4"),
    ("host_fault_withheld_dump_all_hints",
     claim(16, "host_fault", {"stop_reason": "0x30004", "thread_name": "d2vita_main",
                              "pc": host("jit", "jit", 0x3a0), "lr": host("jit", "jit", 0x39c),
                              "guest_frames": frames(0x2b1c40, 0x2b0e18), "redaction": "withheld"},
           offers(("crash_txt", 2122), *LOGS), hints=["halt", "abnormal_exit", "guest_fault", "hang"]),
     "hfault_jit|0x30004|Game+0x2b1c40,Game+0x2b0e18"),
    ("abnormal_exit_import_wins_over_code",
     claim(17, "abnormal_exit", {"reason": "unshimmed_import", "code": 0,
                                 "import": "KERNEL32.dll!SetFileTime", "frames": frames(0x10a0c4, 0x1000)},
           EXIT_ARTIFACTS, hints=["guest_fault"]),
     "exit|unshimmed_import|KERNEL32.dll!SetFileTime|Game+0x10a0c4"),
    ("abnormal_exit_exit_code",
     claim(18, "abnormal_exit", {"reason": "exit_process", "code": 3221225477, "import": None,
                                 "frames": frames(0x1000, 0x2000)}, EXIT_ARTIFACTS),
     "exit|exit_process|3221225477|Game+0x1000"),
    ("abnormal_exit_nothing_known",
     claim(19, "abnormal_exit", {"reason": "fatal_app_exit", "code": None, "import": None, "frames": []},
           LOG_ARTIFACTS),
     "exit|fatal_app_exit|-|-"),
    ("abnormal_exit_code_zero",
     claim(20, "abnormal_exit", {"reason": "raise_exception", "code": 0, "import": None, "frames": []},
           EXIT_ARTIFACTS),
     "exit|raise_exception|0|-"),
    ("hang_with_eip",
     claim(21, "hang", {"stalled_beats": 3, "eip": "Game+0x12345", "runner_state": "running"}, LOG_ARTIFACTS,
           uptime_s=None),
     "hang|Game+0x12345"),
    ("hang_same_eip_other_details",
     claim(22, "hang", {"stalled_beats": 40, "eip": "Game+0x12345", "runner_state": "blocked"}, [],
           build_id=OTHER_BUILD, channel="test", model="unknown", fw="unknown", online=True),
     "hang|Game+0x12345"),
    ("hang_unknown_eip",
     claim(23, "hang", {"stalled_beats": 2, "eip": None, "runner_state": None}, LOG_ARTIFACTS),
     "hang|-"),
]


def build_signature_vectors(cases=None):
    cases = SIGNATURE_CASES if cases is None else cases
    built = []
    for name, claim_document, expected in cases:
        actual = check_schemas.canon(claim_document)
        if actual != expected:
            raise GenerationError(f"{name}: hand-written canon {expected!r}, rules give {actual!r}")
        built.append({
            "name": name,
            "claim": copy.deepcopy(claim_document),
            "canon": expected,
            "signature": check_schemas.signature_id(expected),
        })
    return {
        "description": "Signature vectors for contract/signature-rules.v1.md. Every claim is valid "
                       "against schemas/claim.v1.schema.json; implementations must reproduce canon "
                       "and signature exactly.",
        "rules_version": check_schemas.RULES_VERSION,
        "cases": built,
    }


# --------------------------------------------------------------------------
# Invalid claim vectors
# --------------------------------------------------------------------------

def _set(pointer, value):
    def mutate(document):
        *parents, last = pointer.lstrip("/").split("/")
        node = document
        for key in parents:
            node = node[int(key)] if isinstance(node, list) else node[key]
        if isinstance(node, list):
            node[int(last)] = value
        else:
            node[last] = value
    return mutate


def _delete(pointer):
    def mutate(document):
        *parents, last = pointer.lstrip("/").split("/")
        node = document
        for key in parents:
            node = node[key]
        del node[last]
    return mutate


def _append(pointer, value):
    def mutate(document):
        node = document
        for key in pointer.lstrip("/").split("/"):
            node = node[key]
        node.append(value)
    return mutate


HALT_FEATURES = SPEC_EXAMPLE_CLAIM["features"]

# (name, base case, instance pointer of the expected error, mutation)
INVALID_CLAIM_CASES = [
    ("unknown_top_level_field", "spec_example_halt", "", _set("/debug", True)),
    ("unknown_platform_field", "spec_example_halt", "/platform", _set("/platform/cpu", "arm")),
    ("unknown_session_field", "spec_example_halt", "/session", _set("/session/ip", "192.0.2.1")),
    ("unknown_features_field", "spec_example_halt", "/features", _set("/features/extra", 1)),
    ("unknown_artifact_field", "spec_example_halt", "/artifacts/0", _set("/artifacts/0/sha256", "00")),
    ("unknown_host_address_field", "host_fault_eboot", "/features/pc", _set("/features/pc/absolute", "0x1")),
    ("missing_hints", "spec_example_halt", "", _delete("/hints")),
    ("missing_feature_key", "spec_example_halt", "/features", _delete("/features/location")),
    ("version_2", "spec_example_halt", "/v", _set("/v", 2)),
    ("version_true", "spec_example_halt", "/v", _set("/v", True)),
    ("kind_unknown", "spec_example_halt", "/kind", _set("/kind", "segfault")),
    ("features_of_another_kind", "guest_fault_worker_four_frames", "/features",
     _set("/features", copy.deepcopy(HALT_FEATURES))),
    ("report_id_lowercase", "spec_example_halt", "/report_id", _set("/report_id", "01j9z6t4q8m3k7v2b5n0xwaycd")),
    ("report_id_first_character_8", "spec_example_halt", "/report_id",
     _set("/report_id", "81J9Z6T4Q8M3K7V2B5N0XWAYCD")),
    ("report_id_letter_u", "spec_example_halt", "/report_id", _set("/report_id", "01J9Z6T4Q8M3K7V2B5N0XWAYCU")),
    ("report_id_trailing_newline", "spec_example_halt", "/report_id",
     _set("/report_id", "01J9Z6T4Q8M3K7V2B5N0XWAYCD\n")),
    ("install_id_uppercase", "spec_example_halt", "/install_id",
     _set("/install_id", "4F3C9A0E8B7D6C5A4F3E2D1C0B9A8F7E")),
    ("install_id_trailing_newline", "spec_example_halt", "/install_id",
     _set("/install_id", "4f3c9a0e8b7d6c5a4f3e2d1c0b9a8f7e\n")),
    ("build_id_11_hex_digits", "spec_example_halt", "/build_id", _set("/build_id", "0.1.0+ab12cd34ef5")),
    ("build_id_bad_suffix", "spec_example_halt", "/build_id", _set("/build_id", "0.1.0+ab12cd34ef56-dirt")),
    ("channel_beta", "spec_example_halt", "/channel", _set("/channel", "beta")),
    ("platform_model_ps4", "spec_example_halt", "/platform/model", _set("/platform/model", "ps4")),
    ("platform_fw_one_digit_minor", "spec_example_halt", "/platform/fw", _set("/platform/fw", "3.6")),
    ("session_online_string", "spec_example_halt", "/session/online", _set("/session/online", "no")),
    ("address_uppercase_hex", "spec_example_halt", "/features/frames/0",
     _set("/features/frames/0", "Game+0x1FEDF4")),
    ("address_leading_zero", "spec_example_halt", "/features/frames/0",
     _set("/features/frames/0", "Game+0x01fedf4")),
    ("address_without_0x", "spec_example_halt", "/features/frames/0", _set("/features/frames/0", "Game+1fedf4")),
    ("address_trailing_newline", "spec_example_halt", "/features/frames/0",
     _set("/features/frames/0", "Game+0x1fedf4\n")),
    ("address_module_33_characters", "spec_example_halt", "/features/frames/0",
     _set("/features/frames/0", "M" * 33 + "+0x1")),
    ("address_with_pipe", "spec_example_halt", "/features/frames/0", _set("/features/frames/0", "Ga|me+0x1")),
    ("frames_17", "halt_sixteen_frames", "/features/frames", _append("/features/frames", "Game+0x1")),
    ("guest_frames_9", "host_fault_jit", "/features/guest_frames",
     _set("/features/guest_frames", frames(*range(1, 10)))),
    ("halt_code_negative", "spec_example_halt", "/features/code", _set("/features/code", -1)),
    ("halt_code_fraction", "spec_example_halt", "/features/code", _set("/features/code", 1420.5)),
    ("halt_code_string", "spec_example_halt", "/features/code", _set("/features/code", "1420")),
    ("halt_location_with_directory", "halt_location_five_frames", "/features/location",
     _set("/features/location", "Source\\Codec.cpp:1377")),
    ("halt_location_leading_zero_line", "halt_location_five_frames", "/features/location",
     _set("/features/location", "Codec.cpp:01377")),
    ("guest_exception_uppercase", "guest_fault_worker_four_frames", "/features/exception",
     _set("/features/exception", "0xC0000005")),
    ("guest_eip_null", "guest_fault_worker_four_frames", "/features/eip", _set("/features/eip", None)),
    ("guest_thread_unknown", "guest_fault_worker_four_frames", "/features/thread",
     _set("/features/thread", "audio")),
    ("host_pc_region_heap", "host_fault_eboot", "/features/pc/region", _set("/features/pc/region", "heap")),
    ("host_pc_offset_leading_zero", "host_fault_eboot", "/features/pc/offset",
     _set("/features/pc/offset", "0x02c4184")),
    ("host_redaction_partial", "host_fault_eboot", "/features/redaction", _set("/features/redaction", "partial")),
    ("host_thread_name_non_ascii", "host_fault_eboot", "/features/thread_name",
     _set("/features/thread_name", "caf\xe9")),
    ("exit_reason_unknown", "abnormal_exit_exit_code", "/features/reason", _set("/features/reason", "crashed")),
    ("exit_import_with_pipe", "abnormal_exit_import_wins_over_code", "/features/import",
     _set("/features/import", "KERNEL32.dll|SetFileTime")),
    ("exit_import_with_comma", "abnormal_exit_import_wins_over_code", "/features/import",
     _set("/features/import", "KERNEL32.dll,SetFileTime")),
    ("hang_one_stalled_beat", "hang_with_eip", "/features/stalled_beats", _set("/features/stalled_beats", 1)),
    ("hint_equal_to_kind", "spec_example_halt", "/hints/0", _set("/hints", ["halt"])),
    ("hint_more_severe_than_kind", "guest_fault_main_one_frame", "/hints/0", _set("/hints", ["host_fault"])),
    ("hints_on_hang", "hang_with_eip", "/hints", _set("/hints", ["guest_fault"])),
    ("hints_duplicated", "host_fault_jit", "/hints", _set("/hints", ["hang", "hang"])),
    ("artifact_name_duplicated", "spec_example_halt", "/artifacts",
     _append("/artifacts", {"name": "crash_log", "bytes": 100})),
    ("artifact_name_unknown", "spec_example_halt", "/artifacts/0/name", _set("/artifacts/0/name", "minidump")),
    ("artifact_below_sealed_minimum", "spec_example_halt", "/artifacts/0/bytes", _set("/artifacts/0/bytes", 87)),
    ("artifact_dump_over_cap", "host_fault_eboot", "/artifacts/0/bytes", _set("/artifacts/0/bytes", 2097153)),
    ("artifact_crash_txt_over_cap", "spec_example_halt", "/artifacts/0/bytes", _set("/artifacts/0/bytes", 65537)),
    ("artifact_boot_progress_over_cap", "spec_example_halt", "/artifacts/2/bytes",
     _set("/artifacts/2/bytes", 335873)),
    ("redactions_negative", "spec_example_halt", "/redactions", _set("/redactions", -1)),
]


def build_invalid_claim_vectors(signature_document, cases=None):
    cases = INVALID_CLAIM_CASES if cases is None else cases
    bases = {case["name"]: case["claim"] for case in signature_document["cases"]}
    built = []
    for name, base, pointer, mutate in cases:
        if base not in bases:
            raise GenerationError(f"{name}: unknown base case {base!r}")
        document = copy.deepcopy(bases[base])
        mutate(document)
        if dump(document) == dump(bases[base]):  # not ==: in Python True == 1
            raise GenerationError(f"{name}: the mutation changed nothing")
        built.append({"name": name, "base": base, "invalid_at": pointer, "claim": document})
    return {
        "description": "Claims that schemas/claim.v1.schema.json must reject. Each one is a valid case "
                       "of signatures.v1.json (base) with one change; invalid_at is the JSON pointer "
                       "(RFC 6901) of the instance location where a validator reports an error.",
        "cases": built,
    }


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def render_all():
    """{file name: exact file text} for every vector file."""
    signatures = build_signature_vectors()
    return {
        "signatures.v1.json": dump(signatures),
        "claims-invalid.v1.json": dump(build_invalid_claim_vectors(signatures)),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing; exit 1 on drift")
    parser.add_argument("--dir", type=Path, default=VECTOR_DIR, help="vector directory")
    args = parser.parse_args(argv)
    try:
        rendered = render_all()
    except GenerationError as exc:
        print(f"generation failed: {exc}", file=sys.stderr)
        return 2
    if args.check:
        drift = [name for name, text in rendered.items()
                 if not (args.dir / name).is_file() or (args.dir / name).read_bytes() != text.encode("ascii")]
        for name in drift:
            print(f"DRIFT: {args.dir / name} differs from the generator output", file=sys.stderr)
        if drift:
            print("run contract/tools/gen_vectors.py to regenerate, then review the diff", file=sys.stderr)
            return 1
        print(f"OK: {len(rendered)} vector files up to date")
        return 0
    args.dir.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        (args.dir / name).write_bytes(text.encode("ascii"))
    print(f"wrote {len(rendered)} vector files to {args.dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
