// Runtime translation for the static pages.
//
// Every visible string lives in i18n/<lang>.json. Pages mark elements with
//   data-i18n="key"                       -> text content (with inline markup)
//   data-i18n-attr="attr:key;attr2:key2"  -> attribute values (plain text)
// Inline markup allowed in dictionary strings: `code`, **strong**, [label](href).
// It is turned into DOM nodes directly: dictionary text is never parsed as HTML.

export const LANGUAGES = ["fr", "en"];
export const DEFAULT_LANGUAGE = "en";
export const STORAGE_KEY = "d2vita.lang";

const isSupported = (lang) => LANGUAGES.includes(lang);

export function detectLanguage({ stored = null, preferred = [] } = {}) {
  if (isSupported(stored)) return stored;
  for (const tag of preferred || []) {
    const primary = String(tag).toLowerCase().split("-")[0];
    if (isSupported(primary)) return primary;
  }
  return DEFAULT_LANGUAGE;
}

export function readStoredLanguage(storage) {
  try {
    const value = storage ? storage.getItem(STORAGE_KEY) : null;
    return isSupported(value) ? value : null;
  } catch {
    return null;
  }
}

export function storeLanguage(storage, lang) {
  try {
    if (storage) storage.setItem(STORAGE_KEY, lang);
  } catch {
    // Private browsing or blocked storage: the choice just is not remembered.
  }
}

export function translate(dict, key, params = {}) {
  const template = dict && Object.hasOwn(dict, key) ? dict[key] : key;
  return template.replace(/\{(\w+)\}/g, (match, name) =>
    Object.hasOwn(params, name) ? String(params[name]) : match,
  );
}

// Only https links and page-relative links: the site is served from a
// sub-path (/D2Vita-website/), so root-relative links would break.
export function isSafeHref(href) {
  if (typeof href !== "string" || href.length === 0) return false;
  if (/^https:\/\/[^\s/]+/i.test(href)) return true;
  if (href.startsWith("/")) return false;
  return !/^[a-z][a-z0-9+.-]*:/i.test(href);
}

const INLINE = /`([^`]+)`|\*\*(.+?)\*\*|\[([^\]]+)\]\(([^)\s]+)\)/g;

export function renderInline(text, doc = document) {
  const fragment = doc.createDocumentFragment();
  let last = 0;
  for (const match of text.matchAll(INLINE)) {
    if (match.index > last) fragment.append(text.slice(last, match.index));
    const [whole, code, strong, label, href] = match;
    if (code !== undefined) {
      // Paths are long: offer a line break after each slash.
      const el = doc.createElement("code");
      code.split("/").forEach((part, index, parts) => {
        el.append(index < parts.length - 1 ? `${part}/` : part);
        if (index < parts.length - 1) el.append(doc.createElement("wbr"));
      });
      fragment.append(el);
    } else if (strong !== undefined) {
      const el = doc.createElement("strong");
      el.textContent = strong;
      fragment.append(el);
    } else if (isSafeHref(href)) {
      const el = doc.createElement("a");
      el.setAttribute("href", href);
      el.textContent = label;
      fragment.append(el);
    } else {
      fragment.append(whole);
    }
    last = match.index + whole.length;
  }
  if (last < text.length) fragment.append(text.slice(last));
  return fragment;
}

const PLAIN_TEXT_ELEMENTS = new Set(["TITLE", "OPTION"]);

export function applyTranslations(doc, dict, lang) {
  doc.documentElement.setAttribute("lang", lang);
  for (const el of doc.querySelectorAll("[data-i18n]")) {
    const value = translate(dict, el.getAttribute("data-i18n"));
    if (PLAIN_TEXT_ELEMENTS.has(el.tagName)) {
      el.textContent = value;
    } else {
      el.replaceChildren(renderInline(value, doc));
    }
  }
  for (const el of doc.querySelectorAll("[data-i18n-attr]")) {
    for (const pair of el.getAttribute("data-i18n-attr").split(";")) {
      const separator = pair.indexOf(":");
      if (separator < 1) continue;
      const attr = pair.slice(0, separator).trim();
      const key = pair.slice(separator + 1).trim();
      el.setAttribute(attr, translate(dict, key));
    }
  }
}

function defaultLoadDictionary(lang) {
  const url = new URL(`../i18n/${lang}.json`, import.meta.url);
  return fetch(url).then((response) => {
    if (!response.ok) throw new Error(`i18n: HTTP ${response.status} for ${url}`);
    return response.json();
  });
}

const otherLanguage = (lang) => LANGUAGES.find((l) => l !== lang) || DEFAULT_LANGUAGE;

// The browser jumps to #fragment before the text exists; jump again once it does.
function scrollToFragment(doc, hash) {
  if (!hash || hash.length < 2) return;
  let id;
  try {
    id = decodeURIComponent(hash.slice(1));
  } catch {
    return;
  }
  const target = doc.getElementById(id);
  if (target && typeof target.scrollIntoView === "function") {
    target.scrollIntoView({ block: "start", behavior: "instant" });
  }
}

export async function createI18n({
  doc = document,
  storage = null,
  preferred = [],
  hash = doc.defaultView?.location?.hash || "",
  loadDictionary = defaultLoadDictionary,
} = {}) {
  const cache = new Map();
  const listeners = [];
  const dictionaryFor = async (lang) => {
    if (!cache.has(lang)) cache.set(lang, await loadDictionary(lang));
    return cache.get(lang);
  };

  const state = {
    lang: detectLanguage({ stored: readStoredLanguage(storage), preferred }),
    dict: {},
  };

  const updateToggles = () => {
    for (const toggle of doc.querySelectorAll("[data-lang-toggle]")) {
      toggle.setAttribute("lang", otherLanguage(state.lang));
    }
  };

  const show = async (lang) => {
    state.dict = await dictionaryFor(lang);
    state.lang = lang;
    applyTranslations(doc, state.dict, lang);
    updateToggles();
  };

  const i18n = {
    get lang() {
      return state.lang;
    },
    t: (key, params) => translate(state.dict, key, params),
    onChange(listener) {
      listeners.push(listener);
    },
    async setLanguage(lang) {
      if (!isSupported(lang)) return;
      await show(lang);
      storeLanguage(storage, lang);
      for (const listener of listeners) listener(lang);
    },
  };

  await show(state.lang);
  for (const toggle of doc.querySelectorAll("[data-lang-toggle]")) {
    toggle.addEventListener("click", () => {
      i18n.setLanguage(otherLanguage(state.lang));
    });
  }
  scrollToFragment(doc, hash);
  return i18n;
}
