// The four admin REQUEST bodies of admin.v1 — SignaturePatch, BugPatch,
// BuildRegistration, SettingsUpdate — against the schema, the same treatment
// claims (contract-claims.test.ts) and bugs (contract-bugs.test.ts) get: written
// cases, then a mutation sweep where the hand-written validators of
// src/validate.ts and Ajv on the contract schema have to agree on every mutant.
// Admin *answers* are validated on the way out of every test (test/helpers.ts);
// this file is the other half, the bodies the admin tool sends.
import { describe, expect, it } from "vitest";
import { CAP_NAMES } from "../src/limits";
import {
  validateBugPatch,
  validateBuildRegistration,
  validateSettingsPatch,
  validateSignaturePatch,
  type Validation,
} from "../src/validate";
import { matchesContract } from "./contract";
import { BUILD_ID } from "./fixtures";
import { mutants } from "./mutate";

type Validator = (input: unknown) => Validation<unknown>;

interface Subject {
  ref: string;
  validate: Validator;
  valid: Array<[string, Record<string, unknown>]>;
  invalid: Array<[string, unknown]>;
  // Refusals the API adds on top of what JSON Schema can say, each documented
  // in api/README.md ("Choices made where the design left room").
  extraRefusal?: (body: Record<string, unknown>) => boolean;
}

const SIGNATURE_PATCH: Subject = {
  ref: "admin.v1#SignaturePatch",
  validate: validateSignaturePatch,
  valid: [
    ["a status alone", { status: "open" }],
    ["fixed with a version", { status: "fixed", fixed_in_version: "0.2.0" }],
    ["every field", {
      status: "ignored",
      fixed_in_version: "0.1.0",
      merged_into: "SABCDEFGHIJKLMN2",
      issue_url: "https://github.com/Franckrst/D2Vita/issues/7",
      note: "seen twice on 3.60",
      resample: true,
    }],
    ["every field cleared", { fixed_in_version: null, merged_into: null, issue_url: null, note: null }],
    ["a note at its limit, in code points", { note: "\u{1F409}".repeat(2000) }],
    ["a note with tab and line breaks", { note: "one\ttwo\r\nthree" }],
    ["a version and an issue url at their limits", {
      fixed_in_version: `0.0.${"1".repeat(36)}`,
      issue_url: `https://x/${"y".repeat(290)}`,
    }],
  ],
  invalid: [
    ["an empty patch", {}],
    ["an unknown field", { status: "open", unexpected: 1 }],
    ["an unknown status", { status: "closed" }],
    ["a null status", { status: null }],
    ["a version with four parts", { fixed_in_version: "0.1.0.1" }],
    ["a version of 41 characters", { fixed_in_version: `0.0.${"1".repeat(37)}` }],
    ["a signature id with the wrong alphabet", { merged_into: "S0123456789ABCDE" }],
    ["a signature id of the wrong length", { merged_into: "SABCDEFGHIJKLMN" }],
    ["an http issue url", { issue_url: "http://example.com/1" }],
    ["an issue url with a space", { issue_url: "https://example.com/a b" }],
    ["an issue url of 301 characters", { issue_url: `https://x/${"y".repeat(291)}` }],
    ["a note with a bell", { note: "onetwo" }],
    ["a note of 2001 characters", { note: "n".repeat(2001) }],
    ["resample as a string", { resample: "true" }],
    ["a body that is an array", []],
    ["a body that is a string", "status=open"],
  ],
};

const BUG_PATCH: Subject = {
  ref: "admin.v1#BugPatch",
  validate: validateBugPatch,
  valid: [
    ["a status alone", { status: "fixed" }],
    ["an issue url alone", { issue_url: "https://github.com/Franckrst/D2Vita/issues/9" }],
    ["both", { status: "ignored", issue_url: "https://example.com/x" }],
    ["a cleared issue url", { issue_url: null }],
  ],
  invalid: [
    ["an empty patch", {}],
    ["a note, which admin.v1#BugPatch does not have", { status: "open", note: "hello" }],
    ["an unknown status", { status: "wontfix" }],
    ["an http issue url", { issue_url: "http://example.com/1" }],
    ["a body that is null", null],
  ],
};

const BUILD_REGISTRATION: Subject = {
  ref: "admin.v1#BuildRegistration",
  validate: validateBuildRegistration,
  valid: [
    ["a release build", { build_id: BUILD_ID, version: "0.1.0", channel: "release" }],
    ["a dirty test build", { build_id: "1.2.3+0123456789ab-dirty", version: "1.2.3", channel: "test" }],
    ["a dev build", { build_id: "10.20.30+ffffffffffff", version: "10.20.30", channel: "dev" }],
  ],
  invalid: [
    ["a missing channel", { build_id: BUILD_ID, version: "0.1.0" }],
    ["an unknown channel", { build_id: BUILD_ID, version: "0.1.0", channel: "beta" }],
    ["an unknown field", { build_id: BUILD_ID, version: "0.1.0", channel: "release", unexpected: 1 }],
    ["a build id without a commit", { build_id: "0.1.0", version: "0.1.0", channel: "release" }],
    ["a build id with an upper-case commit", { build_id: "0.1.0+AB12CD34EF56", version: "0.1.0", channel: "release" }],
    ["a version that is not X.Y.Z", { build_id: BUILD_ID, version: "0.1", channel: "release" }],
  ],
  // Documented extra rule: version has to be the VERSION part of build_id.
  extraRefusal: (b) =>
    typeof b.build_id === "string" && typeof b.version === "string" && b.build_id.split("+")[0] !== b.version,
};

const SETTINGS_UPDATE: Subject = {
  ref: "admin.v1#SettingsUpdate",
  validate: validateSettingsPatch,
  valid: [
    ["the kill switch alone", { accepting: false }],
    ["an end date", { accepting: false, disable_until_unix: 1789284000 }],
    ["a cleared end date", { disable_until_unix: null }],
    ["one cap", { caps: { global_claims_per_day: 500 } }],
    ["every cap", { caps: Object.fromEntries(CAP_NAMES.map((name) => [name, 1])) }],
    ["a cap at the largest safe integer", { caps: { global_artifact_bytes_per_day: Number.MAX_SAFE_INTEGER } }],
    ["an end date at the top of the 32-bit range", { disable_until_unix: 4294967295 }],
  ],
  invalid: [
    ["an empty patch", {}],
    ["an unknown field", { accepting: true, unexpected: 1 }],
    ["an empty cap object", { caps: {} }],
    ["a cap under its wave-1 name", { caps: { global_claims: 500 } }],
    ["an unknown cap", { caps: { global_claims_per_day: 1, made_up: 2 } }],
    ["a negative cap", { caps: { ip_bugs_per_day: -1 } }],
    ["a fractional cap", { caps: { ip_bugs_per_day: 1.5 } }],
    ["a cap above the largest safe integer", { caps: { ip_bugs_per_day: 9007199254740992 } }],
    ["an end date above 32 bits", { disable_until_unix: 4294967296 }],
    ["accepting as a string", { accepting: "false" }],
    ["caps as an array", { caps: [] }],
  ],
};

// Every field named by any of the four definitions: each one is tried on each
// body, so no definition may borrow a field from another.
const ALL_FIELDS = [
  "status",
  "fixed_in_version",
  "merged_into",
  "issue_url",
  "note",
  "resample",
  "build_id",
  "version",
  "channel",
  "accepting",
  "disable_until_unix",
  "caps",
  "unexpected",
];

const SUBJECTS: Array<[string, Subject]> = [
  ["SignaturePatch", SIGNATURE_PATCH],
  ["BugPatch", BUG_PATCH],
  ["BuildRegistration", BUILD_REGISTRATION],
  ["SettingsUpdate", SETTINGS_UPDATE],
];

describe.each(SUBJECTS)("%s", (_name, subject) => {
  it.each(subject.valid)("accepts %s", (_case, body) => {
    expect(matchesContract(subject.ref, body), `${subject.ref} should accept ${JSON.stringify(body)}`).toBe(true);
    const result = subject.validate(body);
    expect(result.ok ? null : result.error).toBeNull();
  });

  it.each(subject.invalid)("refuses %s", (_case, body) => {
    expect(matchesContract(subject.ref, body), `${subject.ref} should refuse ${JSON.stringify(body)}`).toBe(false);
    expect(subject.validate(body).ok).toBe(false);
  });

  // The written cases only cover what someone thought of; the sweep covers the
  // rest. Every field of every admin definition is tried on every body, so a
  // validator that borrowed a neighbour's field (a `note` on a BugPatch) is
  // caught too. The API may refuse more than the schema where README.md says
  // so, and never less.
  it("agrees with Ajv on every mutant of every accepted body", () => {
    const values: unknown[] = [
      null,
      true,
      false,
      0,
      1,
      -1,
      1.5,
      4294967295,
      4294967296,
      Number.MAX_SAFE_INTEGER,
      9007199254740992,
      "",
      " ",
      "x",
      "open",
      "fixed",
      "ignored",
      "closed",
      "release",
      "dev",
      "beta",
      "0.1.0",
      "0.1.0+ab12cd34ef56",
      `0.0.${"1".repeat(37)}`,
      "SABCDEFGHIJKLMN2",
      "https://example.com/1",
      "http://example.com/1",
      "onetwo",
      "one\ttwo",
      "x".repeat(41),
      "x".repeat(301),
      "x".repeat(2001),
      [],
      {},
      { global_claims_per_day: 1 },
    ];
    const disagreements: string[] = [];
    let checked = 0;
    const compare = (what: string, body: unknown) => {
      checked++;
      const schemaSays = matchesContract(subject.ref, body);
      const apiSays = subject.validate(body).ok;
      if (schemaSays === apiSays) return;
      const extra =
        schemaSays &&
        !apiSays &&
        subject.extraRefusal !== undefined &&
        subject.extraRefusal(body as Record<string, unknown>);
      if (!extra && disagreements.length < 20) {
        disagreements.push(`${what} -> schema ${schemaSays ? "accepts" : "refuses"}, API ${apiSays ? "accepts" : "refuses"}`);
      }
    };
    for (const [, body] of subject.valid) {
      for (const mutant of mutants(body, values)) compare(mutant.what, mutant.value);
      // Fields of the other admin definitions, added to this one.
      for (const key of ALL_FIELDS) {
        for (const value of values) compare(`add /${key} = ${JSON.stringify(value)}`, { ...body, [key]: value });
      }
    }
    expect(checked).toBeGreaterThan(1500);
    expect(disagreements).toEqual([]);
  });
});
