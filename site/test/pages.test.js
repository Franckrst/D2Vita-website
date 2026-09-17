import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LANGUAGES } from "../assets/i18n.js";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (...parts) => readFileSync(path.join(siteRoot, ...parts), "utf8");

const PAGES = ["index.html", "bug.html", "privacy.html"];
const dicts = Object.fromEntries(LANGUAGES.map((l) => [l, JSON.parse(read("i18n", `${l}.json`))]));

// Absolute URLs a page may reference. Everything else must be page-relative.
const ALLOWED_EXTERNAL = [
  /^https:\/\/github\.com\/Franckrst\/D2Vita\/(issues|releases)$/,
  /^https:\/\/franckrst\.github\.io\/D2Vita\/installation\/$/,
  /^https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js(\?.*)?$/,
];

const parsePage = (page) => new DOMParser().parseFromString(read(page), "text/html");

function keysUsedBy(doc) {
  const keys = [];
  for (const el of doc.querySelectorAll("[data-i18n]")) keys.push(el.getAttribute("data-i18n"));
  for (const el of doc.querySelectorAll("[data-i18n-attr]")) {
    for (const pair of el.getAttribute("data-i18n-attr").split(";")) {
      keys.push(pair.slice(pair.indexOf(":") + 1).trim());
    }
  }
  return keys;
}

function textNodes(node, out = []) {
  for (const child of node.childNodes) {
    if (child.nodeType === 3) out.push(child);
    else if (child.nodeType === 1 && !["SCRIPT", "STYLE"].includes(child.tagName)) {
      textNodes(child, out);
    }
  }
  return out;
}

// String literals in the scripts that look like dictionary keys.
function keyLiteralsInScripts() {
  const namespaces = new Set(Object.keys(dicts.fr).map((k) => k.split(".")[0]));
  const literals = new Set();
  for (const file of readdirSync(path.join(siteRoot, "assets")).filter((f) => f.endsWith(".js"))) {
    for (const m of read("assets", file).matchAll(/["'`]([a-z][a-zA-Z0-9]*(?:\.[a-zA-Z0-9]+)+)["'`]/g)) {
      if (namespaces.has(m[1].split(".")[0])) literals.add(m[1]);
    }
  }
  return literals;
}

describe.each(PAGES)("%s", (page) => {
  it("exists", () => {
    expect(existsSync(path.join(siteRoot, page))).toBe(true);
  });

  it("only uses keys that exist in every dictionary", () => {
    const doc = parsePage(page);
    const keys = keysUsedBy(doc);
    expect(keys.length).toBeGreaterThan(0);
    for (const lang of LANGUAGES) {
      expect(keys.filter((k) => !(k in dicts[lang])), `missing in ${lang}.json`).toEqual([]);
    }
  });

  it("translates its <title> and meta description", () => {
    const doc = parsePage(page);
    expect(doc.querySelector("title")?.getAttribute("data-i18n")).toMatch(/^page\./);
    expect(doc.querySelector('meta[name="description"]')?.getAttribute("data-i18n-attr")).toMatch(
      /^content:page\./,
    );
  });

  it("contains no hardcoded text", () => {
    const doc = parsePage(page);
    const stray = textNodes(doc.documentElement)
      .map((n) => n.textContent.trim())
      .filter(Boolean);
    expect(stray).toEqual([]);
    for (const attr of ["alt", "title", "placeholder", "aria-label", "aria-description", "content"]) {
      for (const el of doc.querySelectorAll(`[${attr}]`)) {
        if (el.tagName === "META" && el.getAttribute("name") !== "description") continue;
        throw new Error(`hardcoded ${attr}="${el.getAttribute(attr)}" on <${el.tagName.toLowerCase()}>`);
      }
    }
  });

  it("references only relative paths or allowed https URLs", () => {
    const doc = parsePage(page);
    for (const el of doc.querySelectorAll("[href], [src], [action]")) {
      const value = el.getAttribute("href") ?? el.getAttribute("src") ?? el.getAttribute("action");
      if (/^[a-z][a-z0-9+.-]*:/i.test(value) || value.startsWith("//")) {
        expect(ALLOWED_EXTERNAL.some((re) => re.test(value)), value).toBe(true);
      } else {
        expect(value.startsWith("/"), `root-relative ${value}`).toBe(false);
      }
    }
  });

  it("points local references at files that exist", () => {
    const doc = parsePage(page);
    for (const el of doc.querySelectorAll("[href], [src]")) {
      const value = el.getAttribute("href") ?? el.getAttribute("src");
      if (/^[a-z][a-z0-9+.-]*:/i.test(value) || value.startsWith("#")) continue;
      const file = value.split(/[?#]/)[0] || "index.html";
      const target = file.endsWith("/") ? path.join(file, "index.html") : file;
      expect(existsSync(path.join(siteRoot, target)), value).toBe(true);
    }
  });
});

describe("dictionary usage", () => {
  const usedByPages = new Set(PAGES.flatMap((p) => keysUsedBy(parsePage(p))));
  const usedByScripts = keyLiteralsInScripts();

  it("every key referenced by a script exists", () => {
    for (const lang of LANGUAGES) {
      expect([...usedByScripts].filter((k) => !(k in dicts[lang])), lang).toEqual([]);
    }
  });

  it("every dictionary key is used by a page or a script", () => {
    const unused = Object.keys(dicts.fr).filter((k) => !usedByPages.has(k) && !usedByScripts.has(k));
    expect(unused).toEqual([]);
  });

  it("links inside dictionary strings are relative or allowed https URLs", () => {
    for (const lang of LANGUAGES) {
      for (const [key, value] of Object.entries(dicts[lang])) {
        for (const m of value.matchAll(/\]\(([^)\s]+)\)/g)) {
          const href = m[1];
          if (/^https:/.test(href)) {
            expect(ALLOWED_EXTERNAL.some((re) => re.test(href)), `${lang}:${key} ${href}`).toBe(true);
          } else {
            const file = href.split("#")[0];
            if (file) expect(existsSync(path.join(siteRoot, file)), `${lang}:${key} ${href}`).toBe(true);
          }
        }
      }
    }
  });
});
