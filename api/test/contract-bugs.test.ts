// Bug bodies (POST /v1/bugs) against contract/schemas/bug.v1.schema.json: the
// same treatment as the claims, since a stored bug comes back in every
// admin.v1#BugItem and has to validate there too.
import { describe, expect, it } from "vitest";
import { validateBug } from "../src/validate";
import { contractErrors, matchesContract } from "./contract";
import { bugBody } from "./fixtures";

const VALID: Array<[string, Record<string, unknown>]> = [
  ["the fixture", bugBody()],
  ["without a contact", (() => {
    const body = bugBody();
    delete body.contact;
    return body;
  })()],
  ["with an empty contact", bugBody({ contact: "" })],
  ["in French", bugBody({ lang: "fr" })],
  ["at the length limits", bugBody({ title: "t".repeat(120), description: "d".repeat(4000), version: "v".repeat(40), contact: "c".repeat(120) })],
  ["with emoji, counted in code points", bugBody({ title: "\u{1F409}".repeat(120), description: "café « »" })],
  ["with tab, line feed and return in the description", bugBody({ description: "one\ttwo\nthree\r\nfour" })],
  ["blank but not empty", bugBody({ title: "   ", version: " " })],
];

describe("bug bodies the contract accepts", () => {
  it.each(VALID)("accepts %s", (_name, body) => {
    expect(contractErrors("bug.v1", body)).toBeNull();
    const result = validateBug(body);
    expect(result.ok ? null : result.error).toBeNull();
  });
});

describe("bug bodies the contract refuses", () => {
  it.each([
    ["an unknown field", bugBody({ extra: 1 })],
    ["a missing title", (() => {
      const body = bugBody();
      delete body.title;
      return body;
    })()],
    ["an empty title", bugBody({ title: "" })],
    ["a title of 121 characters", bugBody({ title: "t".repeat(121) })],
    ["a control character in the title", bugBody({ title: "one\ntwo" })],
    ["a bell in the description", bugBody({ description: "bell" })],
    ["a delete character in the version", bugBody({ version: "0.1.0" })],
    ["a contact of 121 characters", bugBody({ contact: "c".repeat(121) })],
    ["a null contact", bugBody({ contact: null })],
    ["another language", bugBody({ lang: "de" })],
    ["a space in the Turnstile token", bugBody({ turnstile_token: "two words" })],
    ["an empty Turnstile token", bugBody({ turnstile_token: "" })],
    ["a version that is a number", bugBody({ version: 1 })],
  ])("refuses %s", (_name, body) => {
    expect(matchesContract("bug.v1", body)).toBe(false);
    expect(validateBug(body).ok).toBe(false);
  });
});

// Same sweep as the claims: the validator and the schema must agree on every
// mutant of a valid body, not only on the cases written down above.
describe("bug validation follows the schema on mutated bodies", () => {
  it("agrees with Ajv on every mutant", () => {
    const values: unknown[] = [
      null,
      true,
      0,
      1,
      1.5,
      "",
      " ",
      "x",
      "fr",
      "en",
      "de",
      "x".repeat(41),
      "x".repeat(121),
      "x".repeat(2049),
      "line\nbreak",
      "tab\there",
      "bell",
      "\u{1F409}",
      [],
      {},
    ];
    const disagreements: string[] = [];
    let checked = 0;
    for (const [, base] of VALID) {
      const keys = ["title", "description", "version", "contact", "lang", "turnstile_token", "unexpected"];
      for (const key of keys) {
        for (const value of values) {
          const mutant: Record<string, unknown> = { ...base, [key]: value };
          checked++;
          const schemaSays = matchesContract("bug.v1", mutant);
          const apiSays = validateBug(mutant).ok;
          if (schemaSays !== apiSays && disagreements.length < 20) {
            disagreements.push(
              `${key} = ${JSON.stringify(value)}: schema ${schemaSays ? "accepts" : "refuses"}, API ${apiSays ? "accepts" : "refuses"}`,
            );
          }
        }
        const without: Record<string, unknown> = { ...base };
        delete without[key];
        checked++;
        if (matchesContract("bug.v1", without) !== validateBug(without).ok && disagreements.length < 20) {
          disagreements.push(`without ${key}: schema and API disagree`);
        }
      }
    }
    expect(checked).toBeGreaterThan(1000);
    expect(disagreements).toEqual([]);
  });
});
