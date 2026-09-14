// Page entry point: translate the page, then start the bug form if present.
import { createI18n } from "./i18n.js";

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
  await createI18n({ doc: document, storage: localStorageOrNull(), preferred });
} catch (error) {
  console.error(error);
} finally {
  document.documentElement.classList.remove("i18n-pending");
}
