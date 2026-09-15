# D2Vita public site

Static FR/EN site for https://franckrst.github.io/D2Vita-website/: home page,
bug report form and privacy notice. Plain HTML, CSS and JavaScript modules, no
build step. The only third-party resource is Cloudflare Turnstile, loaded on
`bug.html` only. The site never reads crash data: its one API call is
`POST /v1/bugs`.

## Layout

| Path | Role |
|---|---|
| `index.html`, `bug.html`, `privacy.html` | Page structure; every visible string comes from `i18n/` |
| `i18n/fr.json`, `i18n/en.json` | All strings, same keys in both files |
| `assets/i18n.js` | Language detection (saved choice, then browser), dictionary loading, `data-i18n` rendering |
| `assets/app.js` | Bug form: validation, Turnstile, `POST {API_BASE}/v1/bugs`, error messages |
| `assets/config.js` | Public values only: `API_BASE`, `TURNSTILE_SITEKEY` |
| `assets/main.js` | Page entry point |
| `assets/style.css`, `assets/fonts/`, `assets/favicon.svg` | Design (fonts are OFL, see `assets/fonts/README.md`) |
| `scripts/pages-build.mjs` | Copies the public files (pages, `assets/`, `i18n/`) for GitHub Pages |
| `test/` | Vitest + happy-dom |

## Working on it

```sh
cd site
npm ci
npm test
python3 -m http.server 8080   # then open http://127.0.0.1:8080/
```

Pages must be served over HTTP: the dictionaries are fetched, so `file://`
does not work. Every link is page-relative because the site lives under
`/D2Vita-website/`.

The production Turnstile key only works on `franckrst.github.io`. For a local
check of the widget, use Cloudflare's test key `1x00000000000000000000AA`
temporarily; the tests refuse any other key in `config.js`, so it cannot be
committed by mistake.

Regenerate `package-lock.json` with npm 11 (`npx npm@11 install`): npm 10.9
crashes while resolving vitest's peer dependencies. `npm ci` works with both.

## Strings

- Add a string to both dictionaries. Tests fail on a key missing from one
  language, a key no page or script uses, and any text or translatable
  attribute written directly in a page.
- Inline markup in strings: `` `code` ``, `**strong**`, `[label](href)` with
  an https or page-relative target. It is rendered as DOM nodes, never as HTML.
- French: non-breaking space before `: ; ! ?` and inside `« »`, typographic
  apostrophes (tests check both).
- The privacy page describes the design in
  `docs/superpowers/specs/2026-09-14-crash-reports-design.md` (d2-vita). When
  the collected data, consent flow or retention change, update both
  dictionaries and the "updated" date.

## Bug report contract

`POST {API_BASE}/v1/bugs` with a body matching
`contract/schemas/bug.v1.schema.json`: `title` (1-120), `description`
(1-4000), `version` (1-40), optional `contact` (up to 120, omitted when
empty), `lang` (`fr` or `en`), `turnstile_token`. Lengths count Unicode code
points; control characters are replaced by spaces before sending. Handled
responses: 201 (shows the `B…` identifier), 400, 403 `turnstile`, other 403,
429 with `retry_after_s`, 5xx, network failure or 20 s timeout.

`test/contract.test.js` checks this against the contract itself with Ajv 2020
(a test dependency, nothing is added to the page): the field bounds and the
language list are the schema's, everything the form agrees to send validates
against `bug.v1` — including values with control characters, emoji and the
maximum lengths — and every error code of `admin.v1#ErrorBody` maps to a
message that exists in both dictionaries.

If `API_BASE` changes, update the `Content-Security-Policy` of `bug.html`
(a test checks that they match).

## Deployment

`.github/workflows/pages.yml` runs on pushes to `main` that touch `site/`:
`npm ci`, `npm test`, `scripts/pages-build.mjs`, then
`actions/upload-pages-artifact` and `actions/deploy-pages`. Prerequisites in
the repository settings: Pages source set to "GitHub Actions". In the
Turnstile widget settings, `franckrst.github.io` must be an allowed hostname.
The API only answers CORS requests from `https://franckrst.github.io`.
