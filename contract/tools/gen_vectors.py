#!/usr/bin/env python3
"""Generate the contract test vectors, deterministically.

    python3 contract/tools/gen_vectors.py            # write contract/vectors/*.json
    python3 contract/tools/gen_vectors.py --check    # exit 1 if a file differs

Every key, nonce and identifier is fixed in this file, so two runs produce
the same bytes. --check regenerates in memory and compares byte for byte.
Needs only the standard library and PyNaCl (no jsonschema).
"""
import argparse
import base64
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

import nacl.bindings as sodium
import nacl.encoding
import nacl.exceptions
import nacl.hash
import nacl.signing

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
KIB = 1024
MIB = 1024 * KIB
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
    return 72 + plaintext_bytes + 16 * (plaintext_bytes // chunk_size + 1)  # HEADER_SIZE, TAG_SIZE


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
    # Every artifact at exactly its sealed cap (design section 4.5).
    ("host_fault_artifacts_at_caps",
     claim(24, "host_fault", {"stop_reason": "0x30004", "thread_name": "d2vita_main",
                              "pc": host("jit", "jit", 0x1a2b3c), "lr": host("eboot", "eboot", 0x10a0c4),
                              "guest_frames": frames(0x2b1c40), "redaction": "clean"},
           [{"name": "dump", "bytes": 2 * MIB}, {"name": "crash_txt", "bytes": 64 * KIB},
            {"name": "crash_log", "bytes": 64 * KIB}, {"name": "boot_progress", "bytes": 320 * KIB}]),
     "hfault_jit|0x30004|Game+0x2b1c40"),
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
            node[int(last)] = copy.deepcopy(value)
        else:
            node[last] = copy.deepcopy(value)
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
        node.append(copy.deepcopy(value))
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
    ("artifact_dump_over_cap", "host_fault_eboot", "/artifacts/0/bytes", _set("/artifacts/0/bytes", 2 * MIB + 1)),
    ("artifact_crash_txt_over_cap", "spec_example_halt", "/artifacts/0/bytes",
     _set("/artifacts/0/bytes", 64 * KIB + 1)),
    ("artifact_crash_log_over_cap", "spec_example_halt", "/artifacts/1/bytes",
     _set("/artifacts/1/bytes", 64 * KIB + 1)),
    ("artifact_boot_progress_over_cap", "spec_example_halt", "/artifacts/2/bytes",
     _set("/artifacts/2/bytes", 320 * KIB + 1)),
    ("redactions_negative", "spec_example_halt", "/redactions", _set("/redactions", -1)),
    # The dump is offered only by a host_fault whose dump is clean (design section 4.5).
    ("dump_offered_by_halt", "spec_example_halt", "/artifacts", _append("/artifacts", DUMP_ARTIFACTS[0])),
    ("dump_offered_by_guest_fault", "guest_fault_worker_four_frames", "/artifacts",
     _append("/artifacts", DUMP_ARTIFACTS[0])),
    ("dump_offered_by_abnormal_exit", "abnormal_exit_exit_code", "/artifacts",
     _append("/artifacts", DUMP_ARTIFACTS[0])),
    ("dump_offered_by_hang", "hang_with_eip", "/artifacts", _append("/artifacts", DUMP_ARTIFACTS[0])),
    ("dump_offered_although_withheld", "host_fault_eboot", "/artifacts", _set("/features/redaction", "withheld")),
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
# D2VSEAL1 (reference implementation of sealed-format.md, with PyNaCl)
# --------------------------------------------------------------------------

MAGIC = b"D2VSEAL1"
HEADER_SIZE = 72
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 16
CHUNK_SIZE = 65536
MAX_CHUNK_SIZE = 1 << 20
PATTERN = b"D2Vita D2VSEAL1 test vector: 0123456789 abcdefghijklmnopqrstuvwxyz\n"


class OpenError(Exception):
    """Opening failed. kind is truncated, malformed, wrong_key or tampered."""

    def __init__(self, kind, detail):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


def pattern(size):
    """Deterministic plaintext of `size` bytes."""
    return (PATTERN * (size // len(PATTERN) + 1))[:size]


def blake2b_256(data):
    return nacl.hash.blake2b(data, digest_size=32, encoder=nacl.encoding.RawEncoder)


def key_id(recipient_pk):
    return blake2b_256(recipient_pk)[:8]


def derive_key(shared, eph_pk, recipient_pk):
    return blake2b_256(MAGIC + shared + eph_pk + recipient_pk)


def chunk_nonce(nonce_prefix, index):
    return nonce_prefix + struct.pack("<Q", index)


def build_header(recipient_pk, eph_pk, nonce_prefix, chunk_size):
    return MAGIC + key_id(recipient_pk) + eph_pk + nonce_prefix + struct.pack("<I", chunk_size) + bytes(4)


def chunk_layout(size, chunk_size):
    """Plaintext length and last flag of each chunk: full chunks, then a shorter (maybe empty) last one."""
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be in [1, {MAX_CHUNK_SIZE}]")
    full = size // chunk_size
    return [chunk_size] * full + [size - full * chunk_size], [0] * full + [1]


def seal_with_flags(plaintext, recipient_pk, eph_sk, nonce_prefix, chunk_size, chunk_lengths, last_flags):
    """Seal with explicit chunk lengths and last flags (lets tests build broken writers)."""
    if len(recipient_pk) != 32 or len(eph_sk) != 32 or len(nonce_prefix) != NONCE_PREFIX_SIZE:
        raise ValueError("recipient_pk and eph_sk are 32 bytes, nonce_prefix is 16 bytes")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be in [1, {MAX_CHUNK_SIZE}]")
    if sum(chunk_lengths) != len(plaintext) or len(chunk_lengths) != len(last_flags):
        raise ValueError("chunk_lengths must cover the plaintext, one last flag per chunk")
    eph_pk = sodium.crypto_scalarmult_base(eph_sk)
    key = derive_key(sodium.crypto_scalarmult(eph_sk, recipient_pk), eph_pk, recipient_pk)
    header = build_header(recipient_pk, eph_pk, nonce_prefix, chunk_size)
    out, offset = [header], 0
    for index, (length, last) in enumerate(zip(chunk_lengths, last_flags)):
        chunk = plaintext[offset : offset + length]
        offset += length
        out.append(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            chunk, header + bytes([last]), chunk_nonce(nonce_prefix, index), key))
    return b"".join(out)


def seal(plaintext, recipient_pk, eph_sk, nonce_prefix, chunk_size=CHUNK_SIZE):
    lengths, flags = chunk_layout(len(plaintext), chunk_size)
    return seal_with_flags(plaintext, recipient_pk, eph_sk, nonce_prefix, chunk_size, lengths, flags)


def open_sealed(sealed, recipient_sk):
    """Open a D2VSEAL1 object; checks in the order given by sealed-format.md."""
    if len(sealed) < HEADER_SIZE:
        raise OpenError("truncated", f"{len(sealed)} bytes, shorter than the header")
    header = sealed[:HEADER_SIZE]
    (chunk_size,) = struct.unpack_from("<I", header, 64)
    if header[:8] != MAGIC:
        raise OpenError("malformed", "bad magic")
    if header[68:72] != bytes(4):
        raise OpenError("malformed", "reserved bytes are not zero")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise OpenError("malformed", f"chunk_size {chunk_size} out of range")
    recipient_pk = sodium.crypto_scalarmult_base(recipient_sk)
    if header[8:16] != key_id(recipient_pk):
        raise OpenError("wrong_key", "key_id does not match the recipient key")
    eph_pk = header[16:48]
    try:
        shared = sodium.crypto_scalarmult(recipient_sk, eph_pk)
    except RuntimeError:  # libsodium refuses an all-zero result
        shared = bytes(32)
    if shared == bytes(32):
        raise OpenError("malformed", "X25519 output is all zero (low-order ephemeral key)")
    key = derive_key(shared, eph_pk, recipient_pk)
    body = sealed[HEADER_SIZE:]
    full = chunk_size + TAG_SIZE
    if len(body) % full < TAG_SIZE:
        raise OpenError("truncated", "the object does not end with a last chunk")
    count = len(body) // full + 1
    plaintext = []
    for index in range(count):
        last = index == count - 1
        chunk = body[index * full :] if last else body[index * full : (index + 1) * full]
        try:
            plaintext.append(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                chunk, header + bytes([last]), chunk_nonce(header[48:64], index), key))
        except nacl.exceptions.CryptoError:
            raise OpenError("tampered", f"chunk {index} failed authentication") from None
    return b"".join(plaintext)


# --------------------------------------------------------------------------
# Sealed vectors
# --------------------------------------------------------------------------

RECIPIENT_A_SK = label_digest("sealed-recipient-a-secret-key")
RECIPIENT_B_SK = label_digest("sealed-recipient-b-secret-key")

# (name, recipient secret key, plaintext size, chunk size)
SEALED_CASES = (
    ("empty", RECIPIENT_A_SK, 0, 65536),
    ("one_byte", RECIPIENT_A_SK, 1, 65536),
    ("exact_chunk", RECIPIENT_A_SK, 16, 16),
    ("chunk_plus_one", RECIPIENT_A_SK, 17, 16),
    ("three_chunks", RECIPIENT_A_SK, 40, 16),
    ("two_chunks_then_empty", RECIPIENT_A_SK, 32, 16),
    ("chunk_size_one", RECIPIENT_B_SK, 3, 1),
    ("seventy_thousand_bytes", RECIPIENT_A_SK, 70000, 65536),
)


def _flip(data, index, mask=0x01):
    changed = bytearray(data)
    changed[index] ^= mask
    return bytes(changed)


def _replace(data, offset, new):
    return data[:offset] + new + data[offset + len(new) :]


# (name, base positive case, recipient secret key used to open, change, expected failure)
NEGATIVE_SEALED_CASES = (
    ("truncated_inside_header", "one_byte", RECIPIENT_A_SK, lambda s: s[:40], "truncated"),
    ("truncated_empty_last_chunk_removed", "exact_chunk", RECIPIENT_A_SK, lambda s: s[:-16], "truncated"),
    ("truncated_last_chunk_removed", "chunk_plus_one", RECIPIENT_A_SK, lambda s: s[:-17], "truncated"),
    ("truncated_one_byte_short", "two_chunks_then_empty", RECIPIENT_A_SK, lambda s: s[:-1], "truncated"),
    ("cut_inside_last_chunk_is_tampered", "three_chunks", RECIPIENT_A_SK, lambda s: s[:-1], "tampered"),
    ("tampered_ciphertext_bit", "three_chunks", RECIPIENT_A_SK, lambda s: _flip(s, HEADER_SIZE), "tampered"),
    ("tampered_last_tag_byte", "one_byte", RECIPIENT_A_SK, lambda s: _flip(s, len(s) - 1, 0x80), "tampered"),
    ("tampered_nonce_prefix", "three_chunks", RECIPIENT_A_SK, lambda s: _flip(s, 48), "tampered"),
    ("tampered_ephemeral_public_key", "three_chunks", RECIPIENT_A_SK, lambda s: _flip(s, 21), "tampered"),
    ("tampered_chunks_swapped", "three_chunks", RECIPIENT_A_SK,
     lambda s: s[:72] + s[104:136] + s[72:104] + s[136:], "tampered"),
    ("tampered_trailing_byte", "one_byte", RECIPIENT_A_SK, lambda s: s + b"\x00", "tampered"),
    ("wrong_key", "one_byte", RECIPIENT_B_SK, lambda s: s, "wrong_key"),
    ("malformed_magic", "one_byte", RECIPIENT_A_SK, lambda s: _replace(s, 0, b"D2VSEAL2"), "malformed"),
    ("malformed_magic_takes_precedence_over_wrong_key", "one_byte", RECIPIENT_B_SK,
     lambda s: _replace(s, 0, b"D2VSEAL0"), "malformed"),
    ("malformed_reserved_not_zero", "one_byte", RECIPIENT_A_SK, lambda s: _flip(s, 71), "malformed"),
    ("malformed_chunk_size_zero", "one_byte", RECIPIENT_A_SK,
     lambda s: _replace(s, 64, struct.pack("<I", 0)), "malformed"),
    ("malformed_chunk_size_too_large", "one_byte", RECIPIENT_A_SK,
     lambda s: _replace(s, 64, struct.pack("<I", MAX_CHUNK_SIZE + 1)), "malformed"),
    ("malformed_low_order_ephemeral_key", "one_byte", RECIPIENT_A_SK,
     lambda s: _replace(s, 16, bytes(32)), "malformed"),
)


def _writer_bug_cases():
    """Objects written by broken sealers (no base case)."""
    pk = sodium.crypto_scalarmult_base(RECIPIENT_A_SK)
    eph_sk = label_digest("sealed-writer-bug-ephemeral-secret-key")
    prefix = label_digest("sealed-writer-bug-nonce-prefix")[:NONCE_PREFIX_SIZE]
    return (
        ("writer_omits_empty_last_chunk",
         seal_with_flags(pattern(16), pk, eph_sk, prefix, 16, [16], [1]), "truncated"),
        ("writer_never_sets_last_flag",
         seal_with_flags(pattern(17), pk, eph_sk, prefix, 16, [16, 1], [0, 0]), "tampered"),
    )


def sealed_case(name, recipient_sk, size, chunk_size):
    recipient_pk = sodium.crypto_scalarmult_base(recipient_sk)
    eph_sk = label_digest(f"sealed-{name}-ephemeral-secret-key")
    nonce_prefix = label_digest(f"sealed-{name}-nonce-prefix")[:NONCE_PREFIX_SIZE]
    plaintext = pattern(size)
    eph_pk = sodium.crypto_scalarmult_base(eph_sk)
    shared = sodium.crypto_scalarmult(eph_sk, recipient_pk)
    sealed = seal(plaintext, recipient_pk, eph_sk, nonce_prefix, chunk_size)
    if open_sealed(sealed, recipient_sk) != plaintext or len(sealed) != sealed_size(size, chunk_size):
        raise GenerationError(f"{name}: round trip failed")
    return {
        "name": name,
        "recipient_sk_hex": recipient_sk.hex(),
        "recipient_pk_hex": recipient_pk.hex(),
        "eph_sk_hex": eph_sk.hex(),
        "nonce_prefix_hex": nonce_prefix.hex(),
        "chunk_size": chunk_size,
        "plaintext_hex": plaintext.hex(),
        "eph_pk_hex": eph_pk.hex(),
        "shared_hex": shared.hex(),
        "key_id_hex": key_id(recipient_pk).hex(),
        "key_hex": derive_key(shared, eph_pk, recipient_pk).hex(),
        "sealed_hex": sealed.hex(),
    }


def check_negative_case(case):
    try:
        open_sealed(bytes.fromhex(case["sealed_hex"]), bytes.fromhex(case["recipient_sk_hex"]))
    except OpenError as exc:
        if exc.kind != case["expect"]:
            raise GenerationError(f"{case['name']}: opens as {exc.kind}, expected {case['expect']}") from None
        return
    raise GenerationError(f"{case['name']}: the object opens")


def build_sealed_vectors():
    cases = [sealed_case(*spec) for spec in SEALED_CASES]
    sealed_by_name = {case["name"]: bytes.fromhex(case["sealed_hex"]) for case in cases}
    negatives = []
    for name, base, recipient_sk, change, expect in NEGATIVE_SEALED_CASES:
        negatives.append({"name": name, "base": base, "recipient_sk_hex": recipient_sk.hex(),
                          "sealed_hex": change(sealed_by_name[base]).hex(), "expect": expect})
    for name, sealed, expect in _writer_bug_cases():
        negatives.append({"name": name, "base": None, "recipient_sk_hex": RECIPIENT_A_SK.hex(),
                          "sealed_hex": sealed.hex(), "expect": expect})
    for case in negatives:
        check_negative_case(case)
    return {
        "description": "D2VSEAL1 vectors (contract/sealed-format.md). cases: implementations must produce "
                       "sealed_hex from recipient_pk_hex, eph_sk_hex, nonce_prefix_hex, chunk_size and "
                       "plaintext_hex, and open it back with recipient_sk_hex; eph_pk_hex, shared_hex, "
                       "key_id_hex and key_hex are intermediate values for debugging. negative_cases: "
                       "opening with recipient_sk_hex must fail with expect (truncated, malformed, "
                       "wrong_key or tampered); base names the case the object was derived from.",
        "format": "D2VSEAL1",
        "cases": cases,
        "negative_cases": negatives,
    }


def annotated_example(case):
    """Commented hex dump of a one-chunk sealed case, as shown in sealed-format.md."""
    sealed = bytes.fromhex(case["sealed_hex"])
    plaintext = bytes.fromhex(case["plaintext_hex"])
    if len(plaintext) >= case["chunk_size"]:
        raise ValueError("the example must fit in one chunk")
    nonce = chunk_nonce(bytes.fromhex(case["nonce_prefix_hex"]), 0)
    lines = [
        f"recipient_sk   {case['recipient_sk_hex']}",
        f"recipient_pk   {case['recipient_pk_hex']}",
        f"eph_sk         {case['eph_sk_hex']}",
        f"nonce_prefix   {case['nonce_prefix_hex']}",
        f"chunk_size     {case['chunk_size']}",
        f"plaintext      {plaintext.hex()} ({plaintext.decode('ascii')!r})",
        "",
        "eph_pk = X25519_base(eph_sk)",
        f"  {case['eph_pk_hex']}",
        "shared = X25519(eph_sk, recipient_pk)",
        f"  {case['shared_hex']}",
        'key = BLAKE2b-256("D2VSEAL1" || shared || eph_pk || recipient_pk)',
        f"  {case['key_hex']}",
        "nonce 0 = nonce_prefix || u64 little-endian 0",
        f"  {nonce.hex()}",
        "AD 0 = header (72 bytes) || 01, because chunk 0 is the last chunk",
        "",
        f"{'off':<4}  {'bytes':<47}  field",
    ]
    rows = (
        (0, 8, 'magic "D2VSEAL1"'),
        (8, 16, "key_id = BLAKE2b-256(recipient_pk)[0:8]"),
        (16, 48, "eph_pk"),
        (48, 64, "nonce_prefix"),
        (64, 68, f"chunk_size = {case['chunk_size']}, u32 little-endian"),
        (68, 72, "reserved, zero"),
        (72, 72 + len(plaintext),
         f"chunk 0: ciphertext ({len(plaintext)} byte{'' if len(plaintext) == 1 else 's'})"),
        (72 + len(plaintext), len(sealed), "chunk 0: Poly1305 tag (16 bytes)"),
    )
    for start, end, label in rows:
        for offset in range(start, end, 16):
            part = sealed[offset : min(offset + 16, end)].hex(" ")
            lines.append(f"{offset:04x}  {part:<47}  {label if offset == start else ''}".rstrip())
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Response signature vectors
# --------------------------------------------------------------------------

SIGNING_SEED_A = label_digest("response-signing-seed-a")
SIGNING_SEED_B = label_digest("response-signing-seed-b")
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493


def compact(document):
    """JSON as a Worker's JSON.stringify writes it: no spaces, non-ASCII kept as is."""
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False)


RESPONSE_BODIES = (
    ("decision_upload", SIGNING_SEED_A, compact({
        "v": 1, "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD", "signature": "SZYGIRBIXGHOM3AH",
        "action": "upload",
        "upload": {"token": "eyJyIjoiMDFKOVo2VDRROE0zSzdWMkI1TjBYV0FZQ0QiLCJlIjoxNzg5Mjg2MDAwfQ.q8vLbWEt",
                   "expires_unix": 1789286000,
                   "artifacts": [{"name": "crash_txt", "max_bytes": 64 * KIB},
                                 {"name": "crash_log", "max_bytes": 64 * KIB},
                                 {"name": "boot_progress", "max_bytes": 320 * KIB}]},
        "retry_after_s": None, "disable_until_unix": None})),
    ("decision_count_only", SIGNING_SEED_A, compact({
        "v": 1, "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD", "signature": "SZYGIRBIXGHOM3AH",
        "action": "count_only", "upload": None, "retry_after_s": None, "disable_until_unix": None})),
    ("error_rate_limited", SIGNING_SEED_A, compact({
        "v": 1, "error": "rate_limited", "message": "daily claim limit reached for this installation",
        "retry_after_s": 32400})),
    ("error_not_accepting", SIGNING_SEED_A, compact({
        "v": 1, "error": "not_accepting", "message": "crash reports are paused",
        "disable_until_unix": 1789372800})),
    ("error_exists", SIGNING_SEED_A, compact({
        "v": 1, "error": "exists", "message": "artifact already stored",
        "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD", "artifact": "crash_txt"})),
    ("artifact_stored", SIGNING_SEED_A, compact({
        "v": 1, "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD", "name": "crash_txt", "bytes": 2210})),
    ("complete_response", SIGNING_SEED_A, compact({
        "v": 1, "report_id": "01J9Z6T4Q8M3K7V2B5N0XWAYCD", "sample_stored": True})),
    ("error_non_ascii_message", SIGNING_SEED_B, compact({
        "v": 1, "error": "invalid_payload", "message": "champ inconnu \xab caf\xe9 \xbb \U0001F525"})),
    ("empty_body", SIGNING_SEED_B, ""),
)


def _sign(seed, body):
    return nacl.signing.SigningKey(seed).sign(body.encode("utf-8")).signature


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def build_response_signature_vectors():
    cases, signatures, seeds = [], {}, {}
    for name, seed, body in RESPONSE_BODIES:
        signature = _sign(seed, body)
        signatures[name], seeds[name] = signature, seed
        cases.append({"name": name, "seed_hex": seed.hex(),
                      "public_key_hex": nacl.signing.SigningKey(seed).verify_key.encode().hex(),
                      "body_utf8": body, "signature_b64": _b64(signature)})
    bodies = {name: body for name, _, body in RESPONSE_BODIES}
    public_a = nacl.signing.SigningKey(SIGNING_SEED_A).verify_key.encode()
    public_b = nacl.signing.SigningKey(SIGNING_SEED_B).verify_key.encode()
    upload = signatures["decision_upload"]
    s_plus_l = (int.from_bytes(upload[32:], "little") + ED25519_ORDER).to_bytes(32, "little")
    negatives = [
        ("body_modified", public_a, bodies["complete_response"].replace("true", "false"),
         signatures["complete_response"]),
        ("trailing_newline_added", public_a, bodies["decision_count_only"] + "\n",
         signatures["decision_count_only"]),
        ("signature_r_bit_flipped", public_a, bodies["decision_upload"], _flip(upload, 0)),
        ("signature_s_plus_group_order", public_a, bodies["decision_upload"], upload[:32] + s_plus_l),
        ("other_public_key", public_b, bodies["decision_upload"], upload),
    ]
    negative_cases = []
    for name, public_key, body, signature in negatives:
        try:
            nacl.signing.VerifyKey(public_key).verify(body.encode("utf-8"), signature)
        except nacl.exceptions.BadSignatureError:
            negative_cases.append({"name": name, "public_key_hex": public_key.hex(), "body_utf8": body,
                                   "signature_b64": _b64(signature), "expect": "invalid"})
            continue
        raise GenerationError(f"{name}: the signature verifies")
    return {
        "description": "Response signature vectors: X-D2V-Signature is the standard base64 (with padding) "
                       "of the Ed25519 signature (RFC 8032, SHA-512, no prehash, no context) of the exact "
                       "UTF-8 bytes of the response body. cases must verify and, signed with seed_hex, "
                       "reproduce signature_b64; negative_cases must not verify.",
        "algorithm": "Ed25519",
        "cases": cases,
        "negative_cases": negative_cases,
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
        "sealed.v1.json": dump(build_sealed_vectors()),
        "response-sig.v1.json": dump(build_response_signature_vectors()),
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
