// The site against the frozen API v1 contract (../../contract): what the bug
// form sends has to be a bug.v1 body, and what it can receive is an
// admin.v1#ErrorBody whose code the page knows how to say out loud.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import { LIMITS, buildPayload, interpretResponse, validateField } from "../assets/app.js";
import { LANGUAGES } from "../assets/i18n.js";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const contractRoot = path.resolve(siteRoot, "..", "contract");
const read = (...parts) => readFileSync(path.join(...parts), "utf8");
const schema = (name) => JSON.parse(read(contractRoot, "schemas", `${name}.v1.schema.json`));

const schemas = ["claim", "decision", "bug", "admin"].map(schema);
const [, , bugSchema, adminSchema] = schemas;
const ajv = new Ajv2020({ strict: true, allErrors: true });
ajv.addSchema(schemas);

const validateBug = ajv.getSchema(bugSchema.$id);
const validateError = ajv.getSchema(`${adminSchema.$id}#/$defs/ErrorBody`);
const dicts = Object.fromEntries(
  LANGUAGES.map((lang) => [lang, JSON.parse(read(siteRoot, "i18n", `${lang}.json`))]),
);

const errors = (validate, value) =>
  validate(value) ? null : validate.errors.map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ");

const values = (overrides = {}) => ({
  title: "Crash when entering the Rogue Encampment",
  description: "The game closes as soon as the act loads.",
  version: "0.1.0",
  contact: "",
  lang: "fr",
  ...overrides,
});

const accepted = (v) =>
  ["title", "description", "version", "contact"].every((name) => validateField(name, v[name]) === null);

describe("the form sends a bug.v1 body", () => {
  it("uses the field bounds of the schema", () => {
    expect(LIMITS).toEqual({
      title: bugSchema.properties.title.maxLength,
      description: bugSchema.properties.description.maxLength,
      version: bugSchema.properties.version.maxLength,
      contact: bugSchema.properties.contact.maxLength,
    });
  });

  it("offers exactly the languages of the schema", () => {
    const page = read(siteRoot, "bug.html");
    const options = [...page.matchAll(/<option value="([a-z]+)"/g)].map((m) => m[1]);
    expect(options).toEqual(bugSchema.properties.lang.enum);
    expect(LANGUAGES).toEqual(bugSchema.properties.lang.enum);
  });

  it.each([
    ["the example of the form", values()],
    ["without a contact", values({ contact: "   " })],
    ["with a contact", values({ contact: " someone@example.org " })],
    ["in English", values({ lang: "en" })],
    ["at the length limits", values({ title: "t".repeat(120), description: "d".repeat(4000), version: "v".repeat(40), contact: "c".repeat(120) })],
    ["with emoji and accents", values({ title: "Écran noir 🐉", description: "Ça plante « à l'entrée ».", contact: "joueur@exemple.fr" })],
    ["with tabs and line feeds in the description", values({ description: "one\ttwo\nthree\r\nfour" })],
    ["with control characters the contract refuses", values({ title: "Crash\u0000in\u0007Act II", description: "bell\u0007", version: "0.1.0\u007f", contact: "me\u001b@example.org" })],
  ])("%s", (_name, v) => {
    const payload = buildPayload(v, "0.dummy-turnstile-token.XyZ-_1");
    expect(errors(validateBug, payload)).toBeNull();
  });

  it("omits contact instead of sending an empty string", () => {
    expect(buildPayload(values({ contact: "  " }), "tok")).not.toHaveProperty("contact");
    expect(buildPayload(values({ contact: "x" }), "tok").contact).toBe("x");
  });

  // The site may refuse more than the contract (it asks for a real title), but
  // it must never send a body the contract refuses.
  it("never sends a body the schema refuses", () => {
    const candidates = [
      "",
      " ",
      "x",
      "x".repeat(39),
      "x".repeat(40),
      "x".repeat(41),
      "x".repeat(120),
      "x".repeat(121),
      "x".repeat(4000),
      "x".repeat(4001),
      "\u0000\u0007\u001b",
      "line\nbreak\ttab",
      "🐉".repeat(120),
      "  padded  ",
    ];
    let sent = 0;
    for (const candidate of candidates) {
      for (const field of ["title", "description", "version", "contact"]) {
        const v = values({ [field]: candidate });
        if (!accepted(v)) continue;
        sent++;
        const payload = buildPayload(v, "tok");
        expect(errors(validateBug, payload), `${field} = ${JSON.stringify(candidate)}`).toBeNull();
      }
    }
    expect(sent).toBeGreaterThan(20);
  });
});

describe("the form reads an admin.v1#ErrorBody", () => {
  // Every code the bug route can answer (contract/README.md: 400, 403 and 429
  // for /v1/bugs; 404, 405 and 500 for a route that is not there or breaks).
  const cases = [
    [400, { v: 1, error: "invalid_payload", message: "title: too long" }, "invalid", "bug.error.invalid"],
    [403, { v: 1, error: "turnstile", message: "Turnstile verification failed" }, "turnstile", "bug.error.turnstile"],
    [413, { v: 1, error: "payload_too_large", message: "Body is limited to 32768 bytes" }, "invalid", "bug.error.invalid"],
    [429, { v: 1, error: "rate_limited", message: "Daily limit reached", retry_after_s: 7200 }, "rateLimited", "bug.error.rateLimited"],
    [404, { v: 1, error: "not_found", message: "No such route" }, "server", "bug.error.server"],
    [405, { v: 1, error: "method_not_allowed", message: "Method not allowed" }, "server", "bug.error.server"],
    [500, { v: 1, error: "internal_error", message: "Internal error" }, "server", "bug.error.server"],
  ];

  it.each(cases)("%i %s", (status, body, reason, key) => {
    expect(errors(validateError, body)).toBeNull();
    const result = interpretResponse(status, body);
    expect(result.ok).toBe(false);
    expect(result.reason).toBe(reason);
    for (const lang of LANGUAGES) expect(dicts[lang][key], `${key} in ${lang}`).toBeTruthy();
  });

  it("reads the delay of a 429 and falls back when it has none", () => {
    const withDelay = interpretResponse(429, { v: 1, error: "rate_limited", message: "x", retry_after_s: 60 });
    expect(withDelay).toEqual({ ok: false, reason: "rateLimited", retryAfterS: 60 });
    // The contract requires retry_after_s on rate_limited; a body without it
    // is not one, and the page still says something useful.
    expect(errors(validateError, { v: 1, error: "rate_limited", message: "x" })).not.toBeNull();
    const without = interpretResponse(429, { v: 1, error: "rate_limited", message: "x" });
    expect(without).toEqual({ ok: false, reason: "rateLimited", retryAfterS: null });
    for (const lang of LANGUAGES) expect(dicts[lang]["bug.error.rateLimitedLater"]).toBeTruthy();
  });

  it("reads a 201 bug.v1#BugCreated and shows its identifier", () => {
    const created = { v: 1, id: "B7YVT8ZQK3M2N5PD" };
    expect(errors(ajv.getSchema(`${bugSchema.$id}#/$defs/BugCreated`), created)).toBeNull();
    expect(interpretResponse(201, created)).toEqual({ ok: true, id: created.id });
    // A success without a readable id still counts as sent.
    expect(interpretResponse(201, null)).toEqual({ ok: true, id: null });
  });

  it("says something readable for every code of the contract", () => {
    const all = adminSchema.$defs.ErrorBody.properties.error.enum;
    const handled = new Set(cases.map(([, body]) => body.error));
    // The six left belong to the console and admin routes; should one ever
    // reach the form, it is still shown as a failure the reader understands.
    expect(all.filter((code) => !handled.has(code)).sort()).toEqual([
      "bad_token",
      "exists",
      "incomplete",
      "not_accepting",
      "unauthorized",
      "unknown_build",
    ]);
    for (const code of all) {
      const result = interpretResponse(503, { v: 1, error: code, message: "x", disable_until_unix: 1789372800 });
      expect(result.ok).toBe(false);
      for (const lang of LANGUAGES) {
        expect(dicts[lang][`bug.error.${result.reason}`], `${code} in ${lang}`).toBeTruthy();
      }
    }
  });
});

// The privacy page tells the reader what the service keeps. The contract
// decides part of that: admin.v1#ReportDetail returns `claim`, which has to
// validate against claim.v1, where install_id is required — so the summary is
// stored whole, installation ID included. The page has to say so, and keep
// saying so.
describe("the privacy page matches what the API stores", () => {
  const claimSchema = schema("claim");

  it("claim.v1 is why the installation id is kept", () => {
    expect(claimSchema.required).toContain("install_id");
    expect(claimSchema.additionalProperties).toBe(false);
    const reportDetail = adminSchema.$defs.ReportDetail;
    expect(reportDetail.required).toContain("claim");
    expect(reportDetail.properties.claim.$ref).toBe("claim.v1.schema.json");
  });

  it("says in both languages that the summary is kept whole for 180 days", () => {
    const html = read(siteRoot, "privacy.html");
    expect(html).toContain('data-i18n="privacy.server.claim"');
    for (const lang of LANGUAGES) {
      const text = dicts[lang]["privacy.server.claim"];
      expect(text, `privacy.server.claim in ${lang}`).toBeTruthy();
      expect(text).toContain("180");
      // The retention entry for summaries says the same number.
      expect(dicts[lang]["privacy.retention.reports.desc"]).toContain("180");
    }
    expect(dicts.en["privacy.server.claim"].toLowerCase()).toContain("installation id");
    expect(dicts.fr["privacy.server.claim"].toLowerCase()).toContain("identifiant d’installation");
  });
});
