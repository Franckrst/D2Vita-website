// Copies the public part of site/ into an output directory for GitHub Pages:
// every top-level page plus assets/ and i18n/. Tests, tooling and package
// files stay out of the published site.
//
// Usage: node scripts/pages-build.mjs <output-directory>
import { cpSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const PUBLIC_DIRECTORIES = ["assets", "i18n"];

export function buildPages(siteDir, outDir) {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
  const pages = readdirSync(siteDir).filter((name) => name.endsWith(".html"));
  for (const entry of [...pages, ...PUBLIC_DIRECTORIES]) {
    cpSync(path.join(siteDir, entry), path.join(outDir, entry), { recursive: true });
  }
  return pages;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const outDir = process.argv[2];
  if (!outDir) {
    console.error("usage: node scripts/pages-build.mjs <output-directory>");
    process.exit(2);
  }
  const siteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const pages = buildPages(siteDir, path.resolve(outDir));
  console.log(`published ${pages.join(", ")} + ${PUBLIC_DIRECTORIES.join(", ")} to ${outDir}`);
}
