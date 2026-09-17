import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createI18n } from "../assets/i18n.js";
import { API_BASE, TURNSTILE_SITEKEY } from "../assets/config.js";
import { LIMITS, formatRetry, initBugForm, loadTurnstile } from "../assets/app.js";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (...parts) => readFileSync(path.join(siteRoot, ...parts), "utf8");
const dicts = { fr: JSON.parse(read("i18n", "fr.json")), en: JSON.parse(read("i18n", "en.json")) };

const $ = (sel) => document.querySelector(sel);

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function fakeTurnstile() {
  const widgets = [];
  const api = {
    render: vi.fn((container, options) => {
      widgets.push({ container, options });
      return `widget-${widgets.length}`;
    }),
    reset: vi.fn(),
    remove: vi.fn(),
  };
  return {
    api,
    widgets,
    load: vi.fn(async () => api),
    solve(token = "turnstile-token-1") {
      widgets.at(-1).options.callback(token);
    },
  };
}

async function setup({ lang = "fr", fetchImpl = vi.fn(), turnstile = fakeTurnstile() } = {}) {
  const page = new DOMParser().parseFromString(read("bug.html"), "text/html");
  document.head.innerHTML = "";
  document.body.innerHTML = page.body.innerHTML;
  const storage = { getItem: () => lang, setItem: () => {} };
  const i18n = await createI18n({
    doc: document,
    storage,
    preferred: [],
    loadDictionary: async (l) => dicts[l],
  });
  const form = initBugForm({ doc: document, i18n, fetchImpl, turnstile });
  await vi.waitFor(() => expect(turnstile.api.render).toHaveBeenCalled());
  return { i18n, form, fetchImpl, turnstile };
}

function type(selector, value) {
  const el = $(selector);
  el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}

function fillValid(overrides = {}) {
  const values = {
    title: "Crash when entering the Rogue Encampment",
    description: "The game closes as soon as the act loads.",
    version: "0.1.0",
    contact: "",
    ...overrides,
  };
  type("#bug-title", values.title);
  type("#bug-description", values.description);
  type("#bug-version", values.version);
  type("#bug-contact", values.contact);
  if (values.lang) $("#bug-lang").value = values.lang;
}

function submit() {
  $("#bug-form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

const errorText = (field) => {
  const el = $(`#bug-${field}-error`);
  return el.hidden ? "" : el.textContent;
};

afterEach(() => {
  vi.useRealTimers();
});

describe("configuration", () => {
  it("uses the public API base and Turnstile site key", () => {
    expect(API_BASE).toBe("https://d2vita-crash.franck-rst-c3d.workers.dev");
    expect(TURNSTILE_SITEKEY).toBe("0x4AAAAAAEz5XmG5sBOmufUm");
  });

  it("matches the spec bounds", () => {
    expect(LIMITS).toEqual({ title: 120, description: 4000, version: 40, contact: 120 });
  });

  it("bug.html allows only the API and Turnstile in its Content-Security-Policy", () => {
    const page = new DOMParser().parseFromString(read("bug.html"), "text/html");
    const csp = page.querySelector('meta[http-equiv="Content-Security-Policy"]').getAttribute("content");
    expect(csp).toContain(`connect-src 'self' ${API_BASE};`);
    expect(csp).toContain("script-src 'self' https://challenges.cloudflare.com;");
    expect(csp).toContain("frame-src https://challenges.cloudflare.com;");
  });

  it("no script talks to any API route other than /v1/bugs", () => {
    const routes = readdirSync(path.join(siteRoot, "assets"))
      .filter((f) => f.endsWith(".js"))
      .flatMap((f) => [...read("assets", f).matchAll(/\/v1\/[A-Za-z0-9_/{}-]*/g)].map((m) => m[0]));
    expect(routes.length).toBeGreaterThan(0);
    expect([...new Set(routes)]).toEqual(["/v1/bugs"]);
  });
});

describe("Turnstile widget", () => {
  it("renders with the site key, the page language and the dark theme", async () => {
    const { turnstile } = await setup();
    const [{ container, options }] = turnstile.widgets;
    expect(container).toBe($("#bug-turnstile"));
    expect(options.sitekey).toBe(TURNSTILE_SITEKEY);
    expect(options.language).toBe("fr");
    expect(options.theme).toBe("dark");
  });

  it("explains when the widget cannot load, and blocks sending", async () => {
    const fetchImpl = vi.fn();
    const turnstile = fakeTurnstile();
    turnstile.load = vi.fn(async () => {
      throw new Error("blocked");
    });
    const page = new DOMParser().parseFromString(read("bug.html"), "text/html");
    document.body.innerHTML = page.body.innerHTML;
    const i18n = await createI18n({
      doc: document,
      storage: { getItem: () => "fr", setItem: () => {} },
      loadDictionary: async (l) => dicts[l],
    });
    initBugForm({ doc: document, i18n, fetchImpl, turnstile });
    await vi.waitFor(() =>
      expect($("#bug-turnstile-status").textContent).toBe(dicts.fr["bug.turnstile.unavailable"]),
    );
    fillValid();
    submit();
    expect(errorText("turnstile")).toBe(dicts.fr["bug.error.turnstileMissing"]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  // A stand-in document: nothing is fetched or executed.
  function fakeDocument() {
    const appended = [];
    return {
      appended,
      createElement: (tag) => Object.assign(new EventTarget(), { tagName: tag.toUpperCase() }),
      head: { append: (el) => appended.push(el) },
    };
  }

  it("loadTurnstile injects the official script once and resolves on its onload callback", async () => {
    const win = {};
    const doc = fakeDocument();
    const pending = loadTurnstile({ win, doc });
    expect(doc.appended).toHaveLength(1);
    expect(doc.appended[0].tagName).toBe("SCRIPT");
    const src = new URL(doc.appended[0].src);
    expect(`${src.origin}${src.pathname}`).toBe("https://challenges.cloudflare.com/turnstile/v0/api.js");
    expect(src.searchParams.get("render")).toBe("explicit");
    const callbackName = src.searchParams.get("onload");
    win.turnstile = { render() {} };
    win[callbackName]();
    await expect(pending).resolves.toBe(win.turnstile);
    expect(loadTurnstile({ win, doc })).toBe(pending);
    expect(doc.appended).toHaveLength(1);
  });

  it("loadTurnstile rejects when the script fails to load", async () => {
    const doc = fakeDocument();
    const pending = loadTurnstile({ win: {}, doc });
    doc.appended[0].dispatchEvent(new Event("error"));
    await expect(pending).rejects.toThrow();
  });
});

describe("validation", () => {
  let ctx;
  beforeEach(async () => {
    ctx = await setup();
  });

  it("requires title, description, version and the bot check", () => {
    submit();
    expect(errorText("title")).toBe(dicts.fr["bug.error.required.title"]);
    expect(errorText("description")).toBe(dicts.fr["bug.error.required.description"]);
    expect(errorText("version")).toBe(dicts.fr["bug.error.required.version"]);
    expect(errorText("contact")).toBe("");
    expect(errorText("turnstile")).toBe(dicts.fr["bug.error.turnstileMissing"]);
    expect($("#bug-title").getAttribute("aria-invalid")).toBe("true");
    expect(document.activeElement).toBe($("#bug-title"));
    expect(ctx.fetchImpl).not.toHaveBeenCalled();
  });

  it("treats whitespace-only values as empty", () => {
    fillValid({ title: "   ", version: "\t" });
    ctx.turnstile.solve();
    submit();
    expect(errorText("title")).toBe(dicts.fr["bug.error.required.title"]);
    expect(errorText("version")).toBe(dicts.fr["bug.error.required.version"]);
    expect(ctx.fetchImpl).not.toHaveBeenCalled();
  });

  it.each([
    ["title", "#bug-title", 120],
    ["description", "#bug-description", 4000],
    ["version", "#bug-version", 40],
    ["contact", "#bug-contact", 120],
  ])("accepts %s at %i characters and rejects one more", (field, selector, max) => {
    fillValid({ [field]: "a".repeat(max + 1) });
    ctx.turnstile.solve();
    submit();
    const expected = dicts.fr["bug.error.tooLong"]
      .replace("{max}", new Intl.NumberFormat("fr").format(max))
      .replace("{excess}", "1");
    expect(errorText(field)).toBe(expected);
    expect(ctx.fetchImpl).not.toHaveBeenCalled();

    type(selector, "a".repeat(max));
    expect(errorText(field)).toBe("");
    expect($(selector).getAttribute("aria-invalid")).toBeNull();
  });

  it("counts characters as Unicode code points, like the API contract", async () => {
    const emoji = "\u{1F409}"; // one code point, two UTF-16 units
    fillValid({ title: emoji.repeat(120) });
    ctx.turnstile.solve();
    expect($("#bug-title-count").textContent).toBe("120 / 120");
    expect($("#bug-title-count").classList.contains("is-over")).toBe(false);
    type("#bug-title", emoji.repeat(121));
    submit();
    expect(errorText("title")).toBe(
      dicts.fr["bug.error.tooLong"].replace("{max}", "120").replace("{excess}", "1"),
    );
  });

  it("counts characters for the title and description", () => {
    type("#bug-title", "abc");
    expect($("#bug-title-count").textContent).toBe("3 / 120");
    type("#bug-description", "x".repeat(4001));
    expect($("#bug-description-count").textContent).toBe(
      `${new Intl.NumberFormat("fr").format(4001)} / ${new Intl.NumberFormat("fr").format(4000)}`,
    );
    expect($("#bug-description-count").classList.contains("is-over")).toBe(true);
  });

  it("validates a field when it loses focus after being edited", () => {
    type("#bug-version", "");
    $("#bug-version").dispatchEvent(new Event("blur"));
    expect(errorText("version")).toBe(dicts.fr["bug.error.required.version"]);
  });
});

describe("request", () => {
  it("POSTs exactly the documented JSON body to /v1/bugs", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(201, { v: 1, id: "B7K2Q9" }));
    const { turnstile } = await setup({ fetchImpl });
    fillValid({
      title: "  Freeze in Act II  ",
      description: "\nThe screen stops updating.\n",
      version: " 0.1.0 ",
      contact: " someone@example.org ",
      lang: "en",
    });
    turnstile.solve("tok-42");
    submit();
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe("https://d2vita-crash.franck-rst-c3d.workers.dev/v1/bugs");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
    expect(init.body).toBe(
      JSON.stringify({
        title: "Freeze in Act II",
        description: "The screen stops updating.",
        version: "0.1.0",
        contact: "someone@example.org",
        lang: "en",
        turnstile_token: "tok-42",
      }),
    );
  });

  it("replaces control characters the contract forbids with spaces", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(201, { v: 1, id: "B12345678" }));
    const { turnstile } = await setup({ fetchImpl });
    fillValid({
      title: "Crash\tin\u0000Act II",
      description: "Line one\nLine two\twith a tab\u0007 and a bell",
      version: "0.1.0\u007f",
      contact: "me\u001b@example.org",
    });
    turnstile.solve("tok");
    submit();
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    const body = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(body.title).toBe("Crash in Act II");
    expect(body.description).toBe("Line one\nLine two\twith a tab  and a bell");
    expect(body.version).toBe("0.1.0");
    expect(body.contact).toBe("me @example.org");
  });

  it("omits contact when it is left empty and sends the page language by default", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(201, { v: 1, id: "B1" }));
    const { turnstile } = await setup({ fetchImpl });
    fillValid({ contact: "   " });
    turnstile.solve("tok");
    submit();
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    const body = JSON.parse(fetchImpl.mock.calls[0][1].body);
    expect(Object.keys(body)).toEqual(["title", "description", "version", "lang", "turnstile_token"]);
    expect(body.lang).toBe("fr");
  });

  it("ignores a second submit while the first one is in flight", async () => {
    let release;
    const fetchImpl = vi.fn(
      () =>
        new Promise((resolve) => {
          release = () => resolve(jsonResponse(201, { v: 1, id: "B2" }));
        }),
    );
    const { turnstile } = await setup({ fetchImpl });
    fillValid();
    turnstile.solve();
    submit();
    submit();
    await vi.waitFor(() => expect(fetchImpl).toHaveBeenCalledTimes(1));
    expect($("#bug-progress").textContent).toBe(dicts.fr["bug.sending"]);
    expect($("#bug-submit").getAttribute("aria-disabled")).toBe("true");
    release();
    await vi.waitFor(() => expect($("#bug-success").hidden).toBe(false));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe("responses", () => {
  it("shows the report ID on success and can start a new report", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(201, { v: 1, id: "B01J9Z6T4Q8" }));
    const { turnstile } = await setup({ fetchImpl });
    fillValid();
    turnstile.solve();
    submit();
    await vi.waitFor(() => expect($("#bug-success").hidden).toBe(false));
    expect($("#bug-form").hidden).toBe(true);
    expect($("#bug-success-id").textContent).toBe("B01J9Z6T4Q8");
    expect(document.activeElement).toBe($("#bug-success"));
    expect($("#bug-progress").textContent).toBe("");
    // The spent token is dropped at once; the widget itself is reset when the
    // form is shown again (resetting it while hidden upsets Turnstile).
    expect(turnstile.api.reset).not.toHaveBeenCalled();

    $("#bug-again").click();
    expect(turnstile.api.reset).toHaveBeenCalledTimes(1);
    expect($("#bug-success").hidden).toBe(true);
    expect($("#bug-form").hidden).toBe(false);
    expect($("#bug-title").value).toBe("");
    expect(document.activeElement).toBe($("#bug-title"));

    fillValid();
    submit();
    expect(errorText("turnstile")).toBe(dicts.fr["bug.error.turnstileMissing"]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("rebuilds the widget in the current language when a new report starts", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse(201, { v: 1, id: "B9" }));
    const { i18n, turnstile } = await setup({ fetchImpl });
    fillValid();
    turnstile.solve();
    submit();
    await vi.waitFor(() => expect($("#bug-success").hidden).toBe(false));

    await i18n.setLanguage("en");
    expect(turnstile.api.remove).not.toHaveBeenCalled();

    $("#bug-again").click();
    expect(turnstile.api.remove).toHaveBeenCalledWith("widget-1");
    expect(turnstile.widgets.at(-1).options.language).toBe("en");
  });

  const failures = [
    ["400 invalid payload", () => jsonResponse(400, { v: 1, error: "invalid_payload", message: "title" }), "bug.error.invalid"],
    ["403 turnstile", () => jsonResponse(403, { v: 1, error: "turnstile", message: "bad token" }), "bug.error.turnstile"],
    ["403 other", () => jsonResponse(403, { v: 1, error: "bad_token", message: "no" }), "bug.error.forbidden"],
    ["429 without delay", () => jsonResponse(429, { v: 1, error: "rate_limited", message: "slow down" }), "bug.error.rateLimitedLater"],
    ["500", () => jsonResponse(500, { v: 1, error: "internal_error", message: "oops" }), "bug.error.server"],
    ["503", () => jsonResponse(503, { v: 1, error: "not_accepting", message: "off" }), "bug.error.server"],
    ["502 with an HTML body", () => new Response("<html>Bad gateway</html>", { status: 502 }), "bug.error.server"],
  ];

  it.each(failures)("renders %s as a readable error and keeps the input", async (_name, response, key) => {
    const fetchImpl = vi.fn(async () => response());
    const { turnstile } = await setup({ fetchImpl });
    fillValid();
    turnstile.solve();
    submit();
    await vi.waitFor(() => expect($("#bug-alert").hidden).toBe(false));
    expect($("#bug-alert").textContent).toBe(dicts.fr[key]);
    expect($("#bug-form").hidden).toBe(false);
    expect($("#bug-success").hidden).toBe(true);
    expect($("#bug-title").value).toBe("Crash when entering the Rogue Encampment");
    expect($("#bug-progress").textContent).toBe("");
    expect($("#bug-submit").getAttribute("aria-disabled")).toBeNull();
    expect(turnstile.api.reset).toHaveBeenCalled();
  });

  it("tells when to retry after a 429 with retry_after_s", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse(429, { v: 1, error: "rate_limited", message: "slow down", retry_after_s: 7200 }),
    );
    const { turnstile } = await setup({ fetchImpl });
    fillValid();
    turnstile.solve();
    submit();
    await vi.waitFor(() => expect($("#bug-alert").hidden).toBe(false));
    expect($("#bug-alert").textContent).toBe(
      dicts.fr["bug.error.rateLimited"].replace("{when}", "dans 2 heures"),
    );
  });

  it("reports a network failure", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    const { turnstile } = await setup({ fetchImpl });
    fillValid();
    turnstile.solve();
    submit();
    await vi.waitFor(() => expect($("#bug-alert").hidden).toBe(false));
    expect($("#bug-alert").textContent).toBe(dicts.fr["bug.error.network"]);
  });

  it("gives up after a timeout and reports it as a network failure", async () => {
    let signal;
    const fetchImpl = vi.fn((_url, init) => {
      signal = init.signal;
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      });
    });
    const { turnstile } = await setup({ fetchImpl });
    vi.useFakeTimers();
    fillValid();
    turnstile.solve();
    submit();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(signal.aborted).toBe(true);
    expect($("#bug-alert").hidden).toBe(false);
    expect($("#bug-alert").textContent).toBe(dicts.fr["bug.error.network"]);
  });
});

describe("language switch", () => {
  it("re-renders dynamic messages and the widget in the new language", async () => {
    const { i18n, turnstile } = await setup();
    submit();
    expect(errorText("title")).toBe(dicts.fr["bug.error.required.title"]);
    expect($("#bug-lang").value).toBe("fr");

    await i18n.setLanguage("en");
    expect(errorText("title")).toBe(dicts.en["bug.error.required.title"]);
    expect(errorText("turnstile")).toBe(dicts.en["bug.error.turnstileMissing"]);
    expect($("#bug-title-count").textContent).toBe("0 / 120");
    expect($("#bug-lang").value).toBe("en");
    expect(turnstile.api.remove).toHaveBeenCalledWith("widget-1");
    expect(turnstile.widgets.at(-1).options.language).toBe("en");
  });

  it("keeps a language the user picked for the message", async () => {
    const { i18n } = await setup();
    $("#bug-lang").value = "en";
    $("#bug-lang").dispatchEvent(new Event("change", { bubbles: true }));
    await i18n.setLanguage("fr");
    await i18n.setLanguage("en");
    await i18n.setLanguage("fr");
    expect($("#bug-lang").value).toBe("en");
  });
});

describe("formatRetry", () => {
  it.each([
    [30, "fr", "dans 1 minute"],
    [600, "fr", "dans 10 minutes"],
    [3600, "fr", "dans 1 heure"],
    [5400, "en", "in 2 hours"],
    [86400 * 3, "en", "in 3 days"],
  ])("formats %i s in %s", (seconds, lang, expected) => {
    expect(formatRetry(seconds, lang)).toBe(expected);
  });
});
