// Page entry point: translate the page, then start the bug form if present.
import { createI18n } from "./i18n.js";
import { initBugForm, loadTurnstile } from "./app.js";

function localStorageOrNull() {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

const preferred = navigator.languages && navigator.languages.length
  ? navigator.languages
  : [navigator.language];

try {
  const i18n = await createI18n({ doc: document, storage: localStorageOrNull(), preferred });
  if (document.getElementById("bug-form")) {
    initBugForm({
      doc: document,
      i18n,
      fetchImpl: (...args) => window.fetch(...args),
      turnstile: { load: () => loadTurnstile() },
    });
  }
} catch (error) {
  console.error(error);
} finally {
  document.documentElement.classList.remove("i18n-pending");
}
