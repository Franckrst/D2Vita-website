# Signature rules, v1

Frozen: `rules_version = 1`.

A signature groups the claims that describe the same bug. The API computes it
for every accepted claim (design, section 5.3); the console never computes it.

- Reference implementation: `tools/check_schemas.py` (`canon()`,
  `signature_id()`). This document and that code state the same rules: the
  test suite compares the template table and the worked example below with
  the code.
- Test vectors: `vectors/signatures.v1.json` (`{name, claim, canon,
  signature}`). Every implementation must reproduce every `canon` and
  `signature` of that file.

## 1. Input

A claim that is valid against `schemas/claim.v1.schema.json`. The rules are
not defined for an invalid claim: validate first. An invalid claim is
answered `400 invalid_payload` and gets no signature.

## 2. Signature id

```
signature = "S" + base32(sha256(utf8(canon)))[0:15]
```

- `sha256`: SHA-256 of the UTF-8 bytes of `canon` (32 bytes).
- `base32`: RFC 4648 section 6 alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`,
  uppercase, without `=` padding. The 32-byte digest encodes to 52
  characters; keep the first 15.
- The result has 16 characters and matches `^S[A-Z2-7]{15}$`.

## 3. Choosing the template

The selector is the claim `kind`. For `host_fault` it is followed by `/` and
`features.pc.region` (`eboot`, `jit`, `sysmodule` or `unknown`). Exactly one
template matches a valid claim.

## 4. Templates

<!-- templates:begin -->
```text
halt                  halt|{features.code}|{features.location}|{features.frames:3}
guest_fault           gfault|{features.exception}|{features.eip}|{features.frames:2}
host_fault/jit        hfault_jit|{features.stop_reason}|{features.guest_frames:3}
host_fault/eboot      hfault|{build_id}|{features.pc.offset}|{features.lr.offset}
host_fault/sysmodule  hfault_sys|{features.pc.module}|{features.pc.offset}
host_fault/unknown    hfault_unknown|{build_id}|{features.pc.offset}|{features.lr.offset}
abnormal_exit         exit|{features.reason}|{features.import ?? features.code}|{features.frames:1}
hang                  hang|{features.eip}
```
<!-- templates:end -->

Each line is `<selector> <template>`, separated by spaces.

## 5. Expanding a template

Text outside braces is copied unchanged; `|` separates the fields. A
placeholder is replaced as follows.

- `{path}`: `path` is a dot-separated list of keys from the claim root, for
  example `build_id` or `features.pc.offset`. The value is formatted as:
  - `null`: the single character `-`;
  - integer: decimal digits, without sign, leading zeros, decimal point or
    exponent. A JSON number written with a fraction or an exponent but with
    an integral value (`1420.0`, `1.42e3`) is the integer `1420`, as in JSON
    Schema;
  - string: copied exactly as received. No trimming, no case change, no
    Unicode normalization, no re-formatting of addresses.
- `{path:N}`: `path` is an array of strings. Its first `N` elements (all of
  them when it has fewer than `N`) joined with `,`. An empty array gives `-`.
- `{a ?? b}`: the value of `a` when it is not `null`, otherwise the value of
  `b`, formatted as for `{path}` (so `-` when both are `null`).

Every path named by a template is a required property of the claim schema,
so a missing key cannot happen in a valid claim.

## 6. Why `|`, `,` and `-` are unambiguous

The claim schema restricts every string that a template uses: addresses
(`^(Game|ABS|(?!(game|abs)\+)[a-z0-9_]{1,32})\+0x(0|[1-9a-f][0-9a-f]{0,7})$`),
32-bit hex values, source locations, module names, import names, reasons and
build ids. None of them can contain `|` or `,`, and none can be the single
character `-`. Integers are digits. So `-` always means absent, and `|` and
`,` only come from the template.

Addresses are already normalized by the console (one spelling per module,
lowercase hex, no leading zeros): the schema rejects any other spelling,
which is why the API can use them as received.

## 7. Module names

An address names its module, so each module needs exactly one spelling:
two spellings would give one bug two signatures. The console writes guest
addresses (`frames`, `eip`, `guest_frames`) as `<module>+0x<offset>` with
these module tokens.

| Module token | Used for | Offset |
|---|---|---|
| `Game` | `Game.exe`, Diablo II LoD 1.14d | address minus the load base of `Game.exe` |
| file name without directory and extension, in lowercase | any other PE image that the guest loader mapped: `glide3x` for `glide3x.dll`, `checkrevision` for `CheckRevision.dll` | address minus the load base of the image |
| `ABS` | an address in no mapped image (heap, stack, code written at run time), or in an image whose lowercase name is not allowed: longer than 32 characters, a character outside `[a-z0-9_]`, or `game` or `abs` | the address itself |

The schema accepts no other spelling:

<!-- address-examples:begin -->
```text
valid    Game+0x1fedf4        Game.exe
valid    glide3x+0x1a2c       glide3x.dll
valid    checkrevision+0x0    CheckRevision.dll
valid    ABS+0x2a4c1000       in no mapped image: the offset is the address
invalid  Game.exe+0x1fedf4    the extension is dropped
invalid  game+0x1fedf4        Game.exe is always Game
invalid  GAME+0x1fedf4        Game.exe is always Game
invalid  Glide3x+0x1a2c       other images are lowercase
invalid  glide3x.dll+0x1a2c   the extension is dropped
invalid  abs+0x2a4c1000       the token is ABS
invalid  Game+0x01fedf4       no leading zero
invalid  Game+0x1FEDF4        lowercase hex digits
```
<!-- address-examples:end -->

Host addresses (`features.pc` and `features.lr` of `host_fault`) give the
module in their own `module` field. For the regions `eboot`, `jit` and
`unknown` it is the region name (the schema requires it). For `sysmodule` it
is the system module name exactly as the dump's module list gives it, with
its case, for example `SceLibKernel`; a system module whose name does not
match `^[A-Za-z0-9_.]{1,32}$` is reported with region `unknown`. The offset
is relative to the start of the eboot, of the translation cache or of the
system module; with region `unknown` it is the address itself.

## 8. Notes per kind

- `halt`: `code` is the Halt code; `location` is `File.cpp:line` or `null`;
  the first 3 guest frames, innermost first, reporter frames already removed
  by the console.
- `guest_fault`: exception code (`0x...`, or `-` when unknown), faulting
  `eip`, first 2 frames.
- `host_fault/jit`: the PC is inside the translation cache, where host
  addresses mean nothing from one run to the next: the stop reason and the
  first 3 guest frames identify the bug.
- `host_fault/eboot`: host offsets move with every build, so the build id is
  part of the canon (one signature per build).
- `host_fault/sysmodule`: system module name and PC offset; independent of
  the D2Vita build.
- `host_fault/unknown`: the PC is in no known region (wild jump, heap, ...).
  The design table has no row for it; v1 uses the `eboot` rule with its own
  `hfault_unknown` tag, so it never collides with an `eboot` signature.
- `abnormal_exit`: `import` when it is not `null`, otherwise `code` in
  decimal, otherwise `-`; then the first frame.
- `hang`: the guest `eip` only (`-` when unknown).

## 9. What a signature ignores

`report_id`, `install_id`, `channel`, `platform`, `session`, `hints`,
`artifacts`, `redactions`, and every feature a template does not name (for
example `thread`, `thread_name`, `redaction`, `stalled_beats`,
`runner_state`). Manual merges (`merged_into`) are applied by the API after
the signature is computed.

## 10. Worked example

The claim of design section 4.4 (`vectors/signatures.v1.json`, case
`spec_example_halt`):

<!-- example:begin -->
```text
canon = halt|1420|-|Game+0x1fedf4,Game+0x451c23,Game+0x44f570
sha256 = ce0c88851731dccd80f3b7170d17f1b88c530f3e362ece65cee7e1073c7316f5
base32 = ZYGIRBIXGHOM3AHTW4LQ2F7RXCGFGDZ6GYXM4ZOO47QQOPDTC32Q
signature = SZYGIRBIXGHOM3AH
```
<!-- example:end -->

## 11. Changing the rules

Changing a template, the formatting or the id formula changes the signature
of existing reports. That is a new `rules_version` described by a new
document (`signature-rules.v2.md`); the API keeps every claim, so it can
reclassify the history (design, section 5.3).
