import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { bugBody } from "./fixtures";
import { NOW, call, resetDatabase } from "./helpers";

const ORIGIN = "https://franckrst.github.io";
const SITEVERIFY = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

function bugRequest(body: Record<string, unknown>, headers: Record<string, string | null> = {}): Request {
  const text = JSON.stringify(body);
  const h = new Headers({
    "content-type": "application/json",
    "content-length": String(new TextEncoder().encode(text).byteLength),
    origin: ORIGIN,
    "cf-connecting-ip": "203.0.113.5",
  });
  for (const [k, v] of Object.entries(headers)) {
    if (v === null) h.delete(k);
    else h.set(k, v);
  }
  return new Request("https://api.test/v1/bugs", { method: "POST", headers: h, body: text });
}

function mockTurnstile(result: { success: boolean } | Error) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
    if (result instanceof Error) throw result;
    return Response.json(result);
  });
}

async function bugCount(): Promise<number> {
  return (await env.DB.prepare("SELECT COUNT(*) AS n FROM bugs").first<{ n: number }>())!.n;
}

beforeEach(async () => {
  await resetDatabase();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("POST /v1/bugs", () => {
  it("stores a bug after Turnstile succeeds and answers 201 with a B… id and CORS", async () => {
    const fetchMock = mockTurnstile({ success: true });
    const res = await call(bugRequest(bugBody()));
    expect(res.status).toBe(201);
    expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    expect(res.headers.get("x-d2v-signature")).toBeNull();
    const body = await res.json<{ v: number; id: string }>();
    expect(body).toEqual({ v: 1, id: expect.stringMatching(/^B[A-Z2-7]{16}$/) });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(String(url)).toBe(SITEVERIFY);
    expect(init?.method).toBe("POST");
    const form = new URLSearchParams(String(init?.body));
    expect(form.get("secret")).toBe("test-turnstile-secret");
    expect(form.get("response")).toBe("XXXX.DUMMY.TOKEN.XXXX");
    expect(form.get("remoteip")).toBe("203.0.113.5");

    const row = await env.DB.prepare("SELECT * FROM bugs WHERE id = ?1").bind(body.id).first();
    expect(row).toMatchObject({
      title: "Crash when opening the stash",
      version: "0.1.0",
      contact: "player@example.com",
      lang: "en",
      status: "open",
      created_at: NOW,
    });
  });

  it("stores an empty contact as NULL", async () => {
    mockTurnstile({ success: true });
    const res = await call(bugRequest(bugBody({ contact: "" })));
    const { id } = await res.json<{ id: string }>();
    expect(await env.DB.prepare("SELECT contact FROM bugs WHERE id = ?1").bind(id).first()).toEqual({ contact: null });
  });

  it("answers 403 turnstile when verification fails or cannot be reached", async () => {
    for (const outcome of [{ success: false }, new Error("network down")]) {
      mockTurnstile(outcome);
      const res = await call(bugRequest(bugBody()));
      expect(res.status).toBe(403);
      expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
      expect(await res.json()).toMatchObject({ v: 1, error: "turnstile" });
      vi.restoreAllMocks();
    }
    expect(await bugCount()).toBe(0);
  });

  it("validates fields before calling Turnstile (400 with CORS)", async () => {
    const fetchMock = mockTurnstile({ success: true });
    const res = await call(bugRequest(bugBody({ title: "x".repeat(121) })));
    expect(res.status).toBe(400);
    expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    expect(await res.json()).toMatchObject({ error: "invalid_payload" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("requires Content-Length", async () => {
    mockTurnstile({ success: true });
    expect((await call(bugRequest(bugBody(), { "content-length": null }))).status).toBe(413);
  });

  it("allows 3 bugs per IP per day and does not count failed Turnstile attempts", async () => {
    mockTurnstile({ success: false });
    for (let i = 0; i < 5; i++) expect((await call(bugRequest(bugBody()))).status).toBe(403);
    vi.restoreAllMocks();
    mockTurnstile({ success: true });
    for (let i = 0; i < 3; i++) expect((await call(bugRequest(bugBody()))).status).toBe(201);
    const refused = await call(bugRequest(bugBody()));
    expect(refused.status).toBe(429);
    expect(refused.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    expect(await refused.json()).toMatchObject({ error: "rate_limited", retry_after_s: expect.any(Number) });
    expect((await call(bugRequest(bugBody(), { "cf-connecting-ip": "203.0.113.6" }))).status).toBe(201);
  });

  it("applies the global daily bug cap", async () => {
    mockTurnstile({ success: true });
    await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('cap:global_bugs', '2')").run();
    expect((await call(bugRequest(bugBody(), { "cf-connecting-ip": "198.51.100.1" }))).status).toBe(201);
    expect((await call(bugRequest(bugBody(), { "cf-connecting-ip": "198.51.100.2" }))).status).toBe(201);
    expect((await call(bugRequest(bugBody(), { "cf-connecting-ip": "198.51.100.3" }))).status).toBe(429);
  });

  it("refuses a request from another origin without calling Turnstile", async () => {
    const fetchMock = mockTurnstile({ success: true });
    const res = await call(bugRequest(bugBody(), { origin: "https://evil.example" }));
    expect(res.status).toBe(403);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(await res.json()).toMatchObject({ error: "origin_not_allowed" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("CORS preflight on /v1/bugs", () => {
  function preflight(origin: string): Request {
    return new Request("https://api.test/v1/bugs", {
      method: "OPTIONS",
      headers: { origin, "access-control-request-method": "POST", "access-control-request-headers": "content-type" },
    });
  }

  it("allows the site origin", async () => {
    const res = await call(preflight(ORIGIN));
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe(ORIGIN);
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")?.toLowerCase()).toContain("content-type");
    expect(res.headers.get("vary")).toContain("Origin");
  });

  it("refuses another origin", async () => {
    const res = await call(preflight("https://franckrst.github.io.evil.example"));
    expect(res.status).toBe(403);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("is not offered on console or admin routes", async () => {
    for (const path of ["/v1/claims", "/v1/admin/stats"]) {
      const res = await call(
        new Request(`https://api.test${path}`, { method: "OPTIONS", headers: { origin: ORIGIN } }),
      );
      expect(res.headers.get("access-control-allow-origin"), path).toBeNull();
    }
  });
});
