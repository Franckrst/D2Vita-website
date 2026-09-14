// Bug report form: validation, Turnstile, and POST {API_BASE}/v1/bugs.
// The site never reads crash data: this is the only API route it calls.
import { API_BASE, TURNSTILE_SCRIPT, TURNSTILE_SITEKEY } from "./config.js";

// Field bounds from the API contract (spec 5.2), counted in UTF-16 code
// units like the browser's own maxlength, on the trimmed value that is sent.
export const LIMITS = { title: 120, description: 4000, version: 40, contact: 120 };
export const REQUEST_TIMEOUT_MS = 20000;
export const TURNSTILE_LOAD_TIMEOUT_MS = 15000;

const TEXT_FIELDS = ["title", "description", "version", "contact"];
const COUNTED_FIELDS = ["title", "description"];
const REQUIRED_KEYS = {
  title: "bug.error.required.title",
  description: "bug.error.required.description",
  version: "bug.error.required.version",
};
const FAILURE_KEYS = {
  invalid: "bug.error.invalid",
  turnstile: "bug.error.turnstile",
  forbidden: "bug.error.forbidden",
  server: "bug.error.server",
  network: "bug.error.network",
};

export function validateField(name, value) {
  const text = value.trim();
  if (REQUIRED_KEYS[name] && text.length === 0) return { key: REQUIRED_KEYS[name] };
  const max = LIMITS[name];
  if (text.length > max) {
    return { key: "bug.error.tooLong", params: { max, excess: text.length - max } };
  }
  return null;
}

export function buildPayload(values, token) {
  const payload = {
    title: values.title.trim(),
    description: values.description.trim(),
    version: values.version.trim(),
  };
  const contact = values.contact.trim();
  if (contact) payload.contact = contact;
  payload.lang = values.lang;
  payload.turnstile_token = token;
  return payload;
}

async function readJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export function interpretResponse(status, body) {
  if (status >= 200 && status < 300) {
    return { ok: true, id: typeof body?.id === "string" ? body.id : null };
  }
  if (status === 400 || status === 413 || status === 422) return { ok: false, reason: "invalid" };
  if (status === 403) {
    return { ok: false, reason: body?.error === "turnstile" ? "turnstile" : "forbidden" };
  }
  if (status === 429) {
    const seconds = Number(body?.retry_after_s);
    return {
      ok: false,
      reason: "rateLimited",
      retryAfterS: Number.isFinite(seconds) && seconds > 0 ? seconds : null,
    };
  }
  return { ok: false, reason: "server" };
}

export async function sendBugReport({
  fetchImpl,
  apiBase = API_BASE,
  payload,
  timeoutMs = REQUEST_TIMEOUT_MS,
}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(`${apiBase}/v1/bugs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      credentials: "omit",
      signal: controller.signal,
    });
    return interpretResponse(response.status, await readJson(response));
  } catch {
    return { ok: false, reason: "network" };
  } finally {
    clearTimeout(timer);
  }
}

export function formatRetry(seconds, lang) {
  const format = new Intl.RelativeTimeFormat(lang, { numeric: "always" });
  if (seconds < 3600) return format.format(Math.max(1, Math.ceil(seconds / 60)), "minute");
  if (seconds < 2 * 86400) return format.format(Math.ceil(seconds / 3600), "hour");
  return format.format(Math.ceil(seconds / 86400), "day");
}

const pendingTurnstile = new WeakMap();

// Loads Turnstile from its official URL (it must not be proxied or cached).
export function loadTurnstile({
  win = window,
  doc = document,
  timeoutMs = TURNSTILE_LOAD_TIMEOUT_MS,
} = {}) {
  if (pendingTurnstile.has(win)) return pendingTurnstile.get(win);
  const pending = new Promise((resolve, reject) => {
    if (win.turnstile) {
      resolve(win.turnstile);
      return;
    }
    const callback = "d2vitaTurnstileReady";
    const timer = setTimeout(() => reject(new Error("Turnstile did not load in time")), timeoutMs);
    win[callback] = () => {
      clearTimeout(timer);
      resolve(win.turnstile);
    };
    const script = doc.createElement("script");
    script.src = `${TURNSTILE_SCRIPT}?render=explicit&onload=${callback}`;
    script.async = true;
    script.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error("Turnstile script failed to load"));
    });
    doc.head.append(script);
  });
  pendingTurnstile.set(win, pending);
  return pending;
}

export function initBugForm({
  doc = document,
  i18n,
  fetchImpl,
  turnstile,
  apiBase = API_BASE,
  sitekey = TURNSTILE_SITEKEY,
}) {
  const byId = (id) => doc.getElementById(id);
  const form = byId("bug-form");
  const controls = Object.fromEntries(TEXT_FIELDS.map((name) => [name, byId(`bug-${name}`)]));
  const langSelect = byId("bug-lang");
  const submitButton = byId("bug-submit");
  const progress = byId("bug-progress");
  const alertBox = byId("bug-alert");
  const widgetBox = byId("bug-turnstile");
  const widgetStatus = byId("bug-turnstile-status");
  const success = byId("bug-success");
  const successId = byId("bug-success-id");

  const state = {
    errors: {},
    edited: new Set(),
    token: null,
    turnstile: "loading",
    sending: false,
    message: null,
    langChosen: false,
  };
  let widgetApi = null;
  let widgetId = null;

  const number = (n) => new Intl.NumberFormat(i18n.lang).format(n);
  const text = (message) => {
    const params = {};
    for (const [name, value] of Object.entries(message.params || {})) {
      params[name] = typeof value === "number" ? number(value) : value;
    }
    if (message.retryAfterS) params.when = formatRetry(message.retryAfterS, i18n.lang);
    return i18n.t(message.key, params);
  };

  function renderError(name) {
    const error = state.errors[name];
    const box = byId(`bug-${name}-error`);
    box.textContent = error ? text(error) : "";
    box.hidden = !error;
    box.closest(".field")?.classList.toggle("is-invalid", Boolean(error));
    const control = controls[name];
    if (!control) return;
    if (error) control.setAttribute("aria-invalid", "true");
    else control.removeAttribute("aria-invalid");
  }

  function renderCounter(name) {
    const count = controls[name].value.trim().length;
    const box = byId(`bug-${name}-count`);
    box.textContent = i18n.t("bug.field.counter", {
      count: number(count),
      max: number(LIMITS[name]),
    });
    box.classList.toggle("is-over", count > LIMITS[name]);
  }

  function renderWidgetStatus() {
    const key = { loading: "bug.turnstile.loading", unavailable: "bug.turnstile.unavailable" }[
      state.turnstile
    ];
    widgetStatus.textContent = key ? i18n.t(key) : "";
    widgetStatus.hidden = !key;
    widgetStatus.classList.toggle("is-error", state.turnstile === "unavailable");
  }

  function renderSending() {
    progress.textContent = state.sending ? i18n.t("bug.sending") : "";
    if (state.sending) {
      submitButton.setAttribute("aria-disabled", "true");
      form.setAttribute("aria-busy", "true");
    } else {
      submitButton.removeAttribute("aria-disabled");
      form.removeAttribute("aria-busy");
    }
  }

  function renderAlert() {
    alertBox.textContent = state.message ? text(state.message) : "";
    alertBox.hidden = !state.message;
  }

  function renderAll() {
    for (const name of [...TEXT_FIELDS, "turnstile"]) renderError(name);
    for (const name of COUNTED_FIELDS) renderCounter(name);
    renderWidgetStatus();
    renderSending();
    renderAlert();
  }

  const widgetOptions = () => ({
    sitekey,
    language: i18n.lang,
    theme: "dark",
    size: "flexible",
    callback(token) {
      state.token = token;
      if (state.errors.turnstile) {
        delete state.errors.turnstile;
        renderError("turnstile");
      }
    },
    "expired-callback": () => {
      state.token = null;
    },
    "timeout-callback": () => {
      state.token = null;
    },
    "error-callback": () => {
      state.token = null;
    },
  });

  function renderWidget() {
    state.token = null;
    if (widgetId !== null) widgetApi.remove(widgetId);
    widgetId = widgetApi.render(widgetBox, widgetOptions());
  }

  function resetWidget() {
    state.token = null;
    if (widgetApi && widgetId !== null) widgetApi.reset(widgetId);
  }

  for (const name of TEXT_FIELDS) {
    const control = controls[name];
    control.addEventListener("input", () => {
      state.edited.add(name);
      if (COUNTED_FIELDS.includes(name)) renderCounter(name);
      if (state.errors[name]) {
        state.errors[name] = validateField(name, control.value) || undefined;
        renderError(name);
      }
    });
    control.addEventListener("blur", () => {
      if (!state.edited.has(name) && !state.errors[name]) return;
      state.errors[name] = validateField(name, control.value) || undefined;
      renderError(name);
    });
  }

  langSelect.addEventListener("change", () => {
    state.langChosen = true;
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.sending) return;
    state.message = null;
    renderAlert();

    let firstInvalid = null;
    for (const name of TEXT_FIELDS) {
      state.errors[name] = validateField(name, controls[name].value) || undefined;
      renderError(name);
      if (state.errors[name] && !firstInvalid) firstInvalid = controls[name];
    }
    state.errors.turnstile = state.token ? undefined : { key: "bug.error.turnstileMissing" };
    renderError("turnstile");
    if (state.errors.turnstile && !firstInvalid) firstInvalid = widgetBox;
    if (firstInvalid) {
      firstInvalid.focus();
      return;
    }

    const values = Object.fromEntries(TEXT_FIELDS.map((name) => [name, controls[name].value]));
    values.lang = langSelect.value;
    const payload = buildPayload(values, state.token);

    state.sending = true;
    renderSending();
    const result = await sendBugReport({ fetchImpl, apiBase, payload });
    state.sending = false;
    renderSending();
    // A Turnstile token is single-use, whatever the outcome.
    resetWidget();

    if (result.ok) {
      successId.textContent = result.id || "";
      successId.parentElement.hidden = !result.id;
      form.hidden = true;
      success.hidden = false;
      success.focus();
      return;
    }
    state.message =
      result.reason === "rateLimited"
        ? result.retryAfterS
          ? { key: "bug.error.rateLimited", retryAfterS: result.retryAfterS }
          : { key: "bug.error.rateLimitedLater" }
        : { key: FAILURE_KEYS[result.reason] || FAILURE_KEYS.server };
    renderAlert();
  });

  byId("bug-again").addEventListener("click", () => {
    for (const name of TEXT_FIELDS) controls[name].value = "";
    state.errors = {};
    state.edited.clear();
    state.message = null;
    state.langChosen = false;
    langSelect.value = i18n.lang;
    renderAll();
    success.hidden = true;
    form.hidden = false;
    controls.title.focus();
  });

  i18n.onChange((lang) => {
    if (!state.langChosen) langSelect.value = lang;
    renderAll();
    if (widgetApi) renderWidget();
  });

  langSelect.value = i18n.lang;
  renderAll();

  Promise.resolve()
    .then(() => turnstile.load())
    .then((api) => {
      widgetApi = api;
      renderWidget();
      state.turnstile = "ready";
    })
    .catch((error) => {
      console.warn(error);
      widgetApi = null;
      state.turnstile = "unavailable";
    })
    .finally(renderWidgetStatus);

  return {
    get token() {
      return state.token;
    },
  };
}
