import { describe, it, expect, beforeEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  LANGUAGES,
  STORAGE_KEY,
  detectLanguage,
  readStoredLanguage,
  storeLanguage,
  translate,
  isSafeHref,
  renderInline,
  applyTranslations,
  createI18n,
} from "../assets/i18n.js";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const loadDict = (lang) =>
  JSON.parse(readFileSync(path.join(siteRoot, "i18n", `${lang}.json`), "utf8"));

const placeholders = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
const hrefs = (s) => [...s.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]).sort();

describe("dictionaries", () => {
  const dicts = Object.fromEntries(LANGUAGES.map((l) => [l, loadDict(l)]));

  it("exist for French and English", () => {
    expect(LANGUAGES).toEqual(["fr", "en"]);
  });

  it("have exactly the same keys in both languages", () => {
    const fr = Object.keys(dicts.fr);
    const en = Object.keys(dicts.en);
    expect(fr.filter((k) => !(k in dicts.en)), "keys missing in en.json").toEqual([]);
    expect(en.filter((k) => !(k in dicts.fr)), "keys missing in fr.json").toEqual([]);
  });

  it("contain only non-empty strings", () => {
    for (const lang of LANGUAGES) {
      for (const [key, value] of Object.entries(dicts[lang])) {
        expect(typeof value, `${lang}:${key}`).toBe("string");
        expect(value.trim().length, `${lang}:${key}`).toBeGreaterThan(0);
      }
    }
  });

  it("use the same placeholders and link targets in both languages", () => {
    for (const key of Object.keys(dicts.fr)) {
      expect(placeholders(dicts.en[key]), `placeholders of ${key}`).toEqual(
        placeholders(dicts.fr[key]),
      );
      expect(hrefs(dicts.en[key]), `links of ${key}`).toEqual(hrefs(dicts.fr[key]));
    }
  });
});

describe("detectLanguage", () => {
  it("prefers a valid stored choice", () => {
    expect(detectLanguage({ stored: "en", preferred: ["fr-FR"] })).toBe("en");
  });

  it("ignores an unsupported stored value", () => {
    expect(detectLanguage({ stored: "de", preferred: ["fr-CA"] })).toBe("fr");
  });

  it("uses the first supported browser language", () => {
    expect(detectLanguage({ stored: null, preferred: ["de-DE", "FR-be", "en"] })).toBe("fr");
    expect(detectLanguage({ stored: null, preferred: ["en-GB", "fr"] })).toBe("en");
  });

  it("falls back to English", () => {
    expect(detectLanguage({ stored: null, preferred: ["de-DE", "ja"] })).toBe("en");
    expect(detectLanguage({})).toBe("en");
  });
});

describe("stored language", () => {
  it("round-trips through storage", () => {
    const data = new Map();
    const storage = {
      getItem: (k) => (data.has(k) ? data.get(k) : null),
      setItem: (k, v) => data.set(k, String(v)),
    };
    storeLanguage(storage, "fr");
    expect(data.get(STORAGE_KEY)).toBe("fr");
    expect(readStoredLanguage(storage)).toBe("fr");
  });

  it("survives a storage that throws or is missing", () => {
    const broken = {
      getItem: () => {
        throw new Error("denied");
      },
      setItem: () => {
        throw new Error("denied");
      },
    };
    expect(readStoredLanguage(broken)).toBeNull();
    expect(() => storeLanguage(broken, "en")).not.toThrow();
    expect(readStoredLanguage(undefined)).toBeNull();
  });
});

describe("translate", () => {
  const dict = { retry: "Réessayez {when}.", plain: "Bonjour" };

  it("returns the string for a key", () => {
    expect(translate(dict, "plain")).toBe("Bonjour");
  });

  it("fills {placeholders}", () => {
    expect(translate(dict, "retry", { when: "dans 3 heures" })).toBe("Réessayez dans 3 heures.");
  });

  it("leaves unknown placeholders untouched", () => {
    expect(translate(dict, "retry", {})).toBe("Réessayez {when}.");
  });

  it("returns the key itself when it is missing", () => {
    expect(translate(dict, "nope")).toBe("nope");
  });
});

describe("isSafeHref", () => {
  it("accepts https and page-relative links", () => {
    for (const href of [
      "https://github.com/Franckrst/D2Vita/issues",
      "bug.html",
      "privacy.html#deletion",
      "#main",
      "./",
    ]) {
      expect(isSafeHref(href), href).toBe(true);
    }
  });

  it("rejects everything else", () => {
    for (const href of [
      "javascript:alert(1)",
      "JavaScript:alert(1)",
      "data:text/html,x",
      "http://example.com",
      "mailto:someone@example.com",
      "/root-relative",
      "//protocol-relative.example",
      "",
    ]) {
      expect(isSafeHref(href), href).toBe(false);
    }
  });
});

describe("renderInline", () => {
  const html = (text) => {
    const div = document.createElement("div");
    div.append(renderInline(text, document));
    return div;
  };

  it("renders `code`, **strong** and [links](href) as elements", () => {
    const div = html("Voir `Crash.txt`, **ceci** et [la page](privacy.html#bugs).");
    expect(div.innerHTML).toBe(
      'Voir <code>Crash.txt</code>, <strong>ceci</strong> et <a href="privacy.html#bugs">la page</a>.',
    );
  });

  it("never interprets HTML", () => {
    const text = '<img src="x" onerror="alert(1)"> & <b>bold</b>';
    const div = html(text);
    expect(div.querySelector("img")).toBeNull();
    expect(div.querySelector("b")).toBeNull();
    expect(div.textContent).toBe(text);
  });

  it("keeps a link with an unsafe target as plain text", () => {
    const div = html("[clic](javascript:alert(1))");
    expect(div.querySelector("a")).toBeNull();
    expect(div.textContent).toContain("clic");
  });
});

describe("applyTranslations", () => {
  const fr = {
    "t.title": "Vie privée — D2Vita",
    "t.desc": "Ce que contiennent les rapports.",
    "t.p": "Rien n'est envoyé **sans votre accord**.",
    "t.label": "Titre",
    "t.option": "Français",
  };
  const en = {
    "t.title": "Privacy — D2Vita",
    "t.desc": "What reports contain.",
    "t.p": "Nothing is sent **without your consent**.",
    "t.label": "Title",
    "t.option": "French",
  };

  beforeEach(() => {
    document.head.innerHTML =
      '<title data-i18n="t.title"></title><meta name="description" data-i18n-attr="content:t.desc">';
    document.body.innerHTML =
      '<p data-i18n="t.p"></p><input id="i" data-i18n-attr="aria-label:t.label;title:t.label">' +
      '<select><option value="fr" data-i18n="t.option"></option></select>';
  });

  it("fills text, inline markup, attributes, the title and <html lang>", () => {
    applyTranslations(document, fr, "fr");
    expect(document.title).toBe("Vie privée — D2Vita");
    expect(document.documentElement.getAttribute("lang")).toBe("fr");
    expect(document.querySelector("meta[name=description]").getAttribute("content")).toBe(
      "Ce que contiennent les rapports.",
    );
    expect(document.querySelector("p").innerHTML).toBe(
      "Rien n'est envoyé <strong>sans votre accord</strong>.",
    );
    expect(document.getElementById("i").getAttribute("aria-label")).toBe("Titre");
    expect(document.getElementById("i").getAttribute("title")).toBe("Titre");
    expect(document.querySelector("option").textContent).toBe("Français");
  });

  it("replaces the previous language completely", () => {
    applyTranslations(document, fr, "fr");
    applyTranslations(document, en, "en");
    expect(document.title).toBe("Privacy — D2Vita");
    expect(document.documentElement.getAttribute("lang")).toBe("en");
    expect(document.querySelector("p").innerHTML).toBe(
      "Nothing is sent <strong>without your consent</strong>.",
    );
    expect(document.querySelectorAll("p strong")).toHaveLength(1);
  });
});

describe("createI18n", () => {
  const dicts = {
    fr: { "nav.home": "Accueil", "lang.toggle": "English", "lang.toggle.aria": "Read in English" },
    en: { "nav.home": "Home", "lang.toggle": "Français", "lang.toggle.aria": "Lire en français" },
  };

  const memoryStorage = (initial = {}) => {
    const data = new Map(Object.entries(initial));
    return {
      data,
      getItem: (k) => (data.has(k) ? data.get(k) : null),
      setItem: (k, v) => data.set(k, String(v)),
    };
  };

  beforeEach(() => {
    document.head.innerHTML = "";
    document.body.innerHTML =
      '<a data-i18n="nav.home"></a><button type="button" data-lang-toggle data-i18n="lang.toggle" data-i18n-attr="aria-label:lang.toggle.aria"></button>';
  });

  it("starts in the detected language and applies it", async () => {
    const load = vi.fn(async (lang) => dicts[lang]);
    const i18n = await createI18n({
      doc: document,
      storage: memoryStorage(),
      preferred: ["fr-FR"],
      loadDictionary: load,
    });
    expect(i18n.lang).toBe("fr");
    expect(i18n.t("nav.home")).toBe("Accueil");
    expect(document.querySelector("a").textContent).toBe("Accueil");
    expect(load).toHaveBeenCalledWith("fr");
  });

  it("switches language, remembers the choice and notifies listeners", async () => {
    const storage = memoryStorage();
    const i18n = await createI18n({
      doc: document,
      storage,
      preferred: ["fr-FR"],
      loadDictionary: async (lang) => dicts[lang],
    });
    const seen = [];
    i18n.onChange((lang) => seen.push(lang));
    await i18n.setLanguage("en");
    expect(i18n.lang).toBe("en");
    expect(storage.data.get(STORAGE_KEY)).toBe("en");
    expect(document.querySelector("a").textContent).toBe("Home");
    expect(document.documentElement.getAttribute("lang")).toBe("en");
    expect(seen).toEqual(["en"]);
  });

  it("wires [data-lang-toggle] to the other language", async () => {
    const storage = memoryStorage({ [STORAGE_KEY]: "en" });
    const i18n = await createI18n({
      doc: document,
      storage,
      preferred: ["fr-FR"],
      loadDictionary: async (lang) => dicts[lang],
    });
    const button = document.querySelector("[data-lang-toggle]");
    expect(button.getAttribute("lang")).toBe("fr");
    button.click();
    await vi.waitFor(() => expect(i18n.lang).toBe("fr"));
    expect(button.getAttribute("lang")).toBe("en");
    expect(button.textContent).toBe("English");
    expect(storage.data.get(STORAGE_KEY)).toBe("fr");
  });
});
