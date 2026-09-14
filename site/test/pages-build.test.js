import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { buildPages } from "../scripts/pages-build.mjs";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(siteRoot, "..");

function walk(dir, base = dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? walk(full, base) : [path.relative(base, full)];
  });
}

describe("pages-build", () => {
  let out;
  beforeAll(() => {
    out = path.join(mkdtempSync(path.join(os.tmpdir(), "d2vita-pages-")), "_site");
    buildPages(siteRoot, out);
  });
  afterAll(() => {
    rmSync(path.dirname(out), { recursive: true, force: true });
  });

  it("publishes the pages, assets and dictionaries", () => {
    const files = walk(out);
    for (const expected of [
      "index.html",
      "bug.html",
      "privacy.html",
      "assets/main.js",
      "assets/app.js",
      "assets/i18n.js",
      "assets/config.js",
      "assets/style.css",
      "assets/favicon.svg",
      "assets/fonts/OFL-Texturina.txt",
      "i18n/fr.json",
      "i18n/en.json",
    ]) {
      expect(files, expected).toContain(expected);
    }
  });

  it("leaves development files out", () => {
    const files = walk(out);
    const leaked = files.filter((f) =>
      /^(test|scripts|node_modules)\/|^package(-lock)?\.json$|^vitest\.config\.js$|^README\.md$/.test(f),
    );
    expect(leaked).toEqual([]);
  });

  it("resolves every local reference inside the published site", () => {
    const missing = [];
    const check = (fromFile, ref) => {
      if (/^[a-z][a-z0-9+.-]*:|^\/\/|^#/i.test(ref)) return;
      const target = ref.split(/[?#]/)[0];
      if (!target) return;
      const resolved = path.resolve(path.dirname(path.join(out, fromFile)), target.endsWith("/") ? `${target}index.html` : target);
      if (!resolved.startsWith(out) || !existsSync(resolved)) missing.push(`${fromFile} -> ${ref}`);
    };
    for (const file of walk(out)) {
      const text = /\.(html|css|js)$/.test(file) ? readFileSync(path.join(out, file), "utf8") : "";
      if (file.endsWith(".html")) {
        for (const m of text.matchAll(/\s(?:href|src)="([^"]+)"/g)) check(file, m[1]);
      }
      if (file.endsWith(".css")) {
        for (const m of text.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/g)) {
          if (!m[1].startsWith("data:")) check(file, m[1]);
        }
      }
      if (file.endsWith(".js")) {
        for (const m of text.matchAll(/\bfrom\s+"(\.[^"]+)"/g)) check(file, m[1]);
      }
    }
    // i18n.js fetches ../i18n/<lang>.json relative to itself.
    check("assets/i18n.js", "../i18n/fr.json");
    check("assets/i18n.js", "../i18n/en.json");
    expect(missing).toEqual([]);
  });
});

describe(".github/workflows/pages.yml", () => {
  const workflowPath = path.join(repoRoot, ".github", "workflows", "pages.yml");
  const workflow = () => readFileSync(workflowPath, "utf8");

  it("exists", () => {
    expect(existsSync(workflowPath)).toBe(true);
  });

  it("deploys from main, and only when the site or the workflow changes", () => {
    const text = workflow();
    expect(text).toMatch(/push:\s*\n\s+branches:\s*\[\s*main\s*\]/);
    expect(text).toContain('- "site/**"');
    expect(text).toContain('- ".github/workflows/pages.yml"');
    expect(text).not.toMatch(/pull_request/);
  });

  it("runs the tests before building the artifact", () => {
    const text = workflow();
    const order = ["npm ci", "npm test", "node scripts/pages-build.mjs", "actions/upload-pages-artifact@", "actions/deploy-pages@"];
    const positions = order.map((needle) => text.indexOf(needle));
    expect(positions.every((p) => p >= 0), positions.join(",")).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it("grants Pages write access to the deploy job only and holds no secret", () => {
    const text = workflow();
    expect(text).toMatch(/^permissions:\s*\n\s+contents:\s*read/m);
    expect(text).toMatch(/deploy:[\s\S]*permissions:\s*\n\s+pages:\s*write\s*\n\s+id-token:\s*write/);
    expect(text).not.toMatch(/secrets\./);
  });
});
