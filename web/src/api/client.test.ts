import { describe, expect, it, vi, beforeEach } from "vitest";
import { ApiError, UnauthorizedError, api, readCookie, setUnauthorizedHandler } from "./client";

function mockFetch(status: number, body: unknown, capture?: (req: RequestInit & { url: string }) => void) {
  const fn = vi.fn(async (url: string, init: RequestInit = {}) => {
    capture?.({ ...init, url });
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    } as Response;
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

beforeEach(() => {
  setUnauthorizedHandler(() => {});
});

describe("api client", () => {
  it("sends the CSRF header from the cookie on writes but not reads", async () => {
    document.cookie = "aigk_csrf=token-abc; path=/";
    const seen: (RequestInit & { url: string })[] = [];
    mockFetch(200, { ok: true }, (r) => seen.push(r));

    await api.status();
    await api.reload();

    const headers = (i: number) => seen[i].headers as Record<string, string>;
    expect(headers(0)["X-CSRF-Token"]).toBeUndefined();
    expect(headers(1)["X-CSRF-Token"]).toBe("token-abc");
    expect(seen[1].credentials).toBe("same-origin");
  });

  it("reports 401 through the unauthorized handler so the app can sign out", async () => {
    mockFetch(401, { error: "authentication required" });
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);

    await expect(api.status()).rejects.toBeInstanceOf(UnauthorizedError);
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("surfaces the server's message and body on other failures", async () => {
    mockFetch(422, { error: "configuration is invalid", errors: [{ path: "rules[0]", message: "bad" }] });
    await expect(api.applyConfig({ yaml: "x", base_version: "v" })).rejects.toMatchObject({
      status: 422,
      message: "configuration is invalid",
    });
    try {
      await api.applyConfig({ yaml: "x", base_version: "v" });
    } catch (err) {
      expect((err as ApiError).body).toMatchObject({ errors: [{ path: "rules[0]" }] });
    }
  });

  it("builds query strings without empty parameters", async () => {
    const seen: { url: string }[] = [];
    mockFetch(200, { items: [] }, (r) => seen.push(r));
    await api.events({ action: "block", service: "", limit: 50 });
    expect(seen[0].url).toBe("/api/v1/events?action=block&limit=50");
  });

  it("reads a cookie value", () => {
    document.cookie = "aigk_csrf=hello%20world; path=/";
    expect(readCookie("aigk_csrf")).toBe("hello world");
    expect(readCookie("absent")).toBe("");
  });
});
