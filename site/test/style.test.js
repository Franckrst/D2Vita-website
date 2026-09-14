import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cssPath = path.join(siteRoot, "assets", "style.css");
const css = () => readFileSync(cssPath, "utf8");

// OKLCH -> linear sRGB (CSS Color 4 matrices), clipped to the sRGB gamut.
function oklchToLinearSrgb(l, c, hDeg) {
  const h = (hDeg * Math.PI) / 180;
  const a = c * Math.cos(h);
  const b = c * Math.sin(h);
  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const clip = (v) => Math.min(1, Math.max(0, v));
  return [
    clip(4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_),
    clip(-1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_),
    clip(-0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_),
  ];
}

const luminance = ([r, g, b]) => 0.2126 * r + 0.7152 * g + 0.0722 * b;
const contrast = (x, y) => {
  const [hi, lo] = [luminance(x), luminance(y)].sort((p, q) => q - p);
  return (hi + 0.05) / (lo + 0.05);
};

function palette() {
  const root = css().match(/:root\s*\{([\s\S]*?)\n\}/);
  expect(root, ":root block").not.toBeNull();
  const tokens = {};
  for (const m of root[1].matchAll(/(--c-[\w-]+):\s*oklch\(([\d.]+)%\s+([\d.]+)\s+([\d.]+)\)/g)) {
    tokens[m[1]] = oklchToLinearSrgb(Number(m[2]) / 100, Number(m[3]), Number(m[4]));
  }
  return tokens;
}

describe("style.css", () => {
  it("exists", () => {
    expect(existsSync(cssPath)).toBe(true);
  });

  it("converts a known colour correctly (sanity check of the helper)", () => {
    // oklch(100% 0 0) is white, oklch(0% 0 0) is black: 21:1.
    expect(contrast(oklchToLinearSrgb(1, 0, 0), oklchToLinearSrgb(0, 0, 0))).toBeCloseTo(21, 1);
  });

  // [foreground, background, minimum ratio]
  const PAIRS = [
    ["--c-text", "--c-ground", 7],
    ["--c-text", "--c-raised", 7],
    ["--c-text-strong", "--c-ground", 7],
    ["--c-text-dim", "--c-ground", 4.5],
    ["--c-text-dim", "--c-raised", 4.5],
    ["--c-text-dim", "--c-raised-2", 4.5],
    ["--c-gold", "--c-ground", 4.5],
    ["--c-gold", "--c-raised", 4.5],
    ["--c-gold-bright", "--c-raised-2", 4.5],
    ["--c-on-gold", "--c-gold", 4.5],
    ["--c-on-gold", "--c-gold-bright", 4.5],
    ["--c-edge", "--c-ground", 3],
    ["--c-edge", "--c-raised", 3],
    ["--c-error", "--c-ground", 4.5],
    ["--c-error", "--c-raised", 4.5],
    ["--c-text-strong", "--c-error-ground", 7],
    ["--c-error", "--c-error-ground", 3],
    ["--c-ok", "--c-raised", 4.5],
  ];

  it.each(PAIRS)("%s on %s reaches %s:1", (fg, bg, min) => {
    const tokens = palette();
    expect(tokens[fg], fg).toBeDefined();
    expect(tokens[bg], bg).toBeDefined();
    expect(contrast(tokens[fg], tokens[bg])).toBeGreaterThanOrEqual(min);
  });

  it("loads nothing from another origin and only references files that exist", () => {
    const source = css();
    expect(source).not.toMatch(/@import/);
    for (const m of source.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/g)) {
      const ref = m[1];
      if (ref.startsWith("data:")) continue;
      expect(/^[a-z][a-z0-9+.-]*:|^\/\//i.test(ref), `external url(${ref})`).toBe(false);
      expect(existsSync(path.join(siteRoot, "assets", ref)), ref).toBe(true);
    }
  });

  it("ships the licence of every bundled font", () => {
    const faces = [...css().matchAll(/url\(\s*["']?(fonts\/[^"')]+)["']?\s*\)/g)].map((m) => m[1]);
    expect(faces.length).toBeGreaterThan(0);
    const licences = readFileSync(path.join(siteRoot, "assets", "fonts", "README.md"), "utf8");
    for (const face of faces) {
      expect(licences, face).toContain(path.basename(face));
    }
  });
});
