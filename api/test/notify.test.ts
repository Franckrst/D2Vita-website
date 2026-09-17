import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { notify } from "../src/notify";
import { sigOf } from "./admin-helpers";
import { haltClaim } from "./fixtures";
import { NOW, call, claimRequest, registerBuild, resetDatabase } from "./helpers";

const TELEGRAM = { TELEGRAM_BOT_TOKEN: "123456:fake-bot-token", TELEGRAM_CHAT_ID: "-100200300" };

function mockFetch(response: Response | Error = Response.json({ ok: true })) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
    if (response instanceof Error) throw response;
    return response.clone();
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("notify", () => {
  it("does nothing unless both Telegram secrets are set", async () => {
    const fetchMock = mockFetch();
    expect(await notify({}, "hello")).toBe(false);
    expect(await notify({ TELEGRAM_BOT_TOKEN: TELEGRAM.TELEGRAM_BOT_TOKEN }, "hello")).toBe(false);
    expect(await notify({ TELEGRAM_CHAT_ID: TELEGRAM.TELEGRAM_CHAT_ID }, "hello")).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends the message through the Bot API when configured", async () => {
    const fetchMock = mockFetch();
    expect(await notify(TELEGRAM, "new signature")).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe("https://api.telegram.org/bot123456:fake-bot-token/sendMessage");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({
      chat_id: "-100200300",
      text: "new signature",
      disable_web_page_preview: true,
    });
  });

  it("swallows delivery failures", async () => {
    mockFetch(new Error("offline"));
    expect(await notify(TELEGRAM, "x")).toBe(false);
    vi.restoreAllMocks();
    mockFetch(new Response("nope", { status: 500 }));
    expect(await notify(TELEGRAM, "x")).toBe(false);
  });
});

describe("notifications from claims", () => {
  beforeEach(async () => {
    await resetDatabase();
    await registerBuild();
  });

  it("notifies a new signature once, not later occurrences", async () => {
    const fetchMock = mockFetch();
    const configured = { ...env, ...TELEGRAM };
    await call(claimRequest(haltClaim()), NOW, configured);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const text = JSON.parse(String(fetchMock.mock.calls[0]![1]?.body)).text as string;
    expect(text).toContain(await sigOf(haltClaim()));
    expect(text).toContain("halt");
    await call(claimRequest(haltClaim()), NOW, configured);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("notifies a regression", async () => {
    const configured = { ...env, ...TELEGRAM };
    await call(claimRequest(haltClaim()));
    const sig = await sigOf(haltClaim());
    await env.DB.prepare("UPDATE signatures SET status = 'fixed', fixed_in_version = '0.1.0' WHERE id = ?1").bind(sig).run();
    const fetchMock = mockFetch();
    await call(claimRequest(haltClaim()), NOW, configured);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String(fetchMock.mock.calls[0]![1]?.body)).text).toContain("regress");
  });

  it("sends nothing without the secrets", async () => {
    const fetchMock = mockFetch();
    await call(claimRequest(haltClaim()));
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
