import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Traffic } from "./Traffic";
import { api } from "../api/client";
import type { AuditEvent } from "../api/types";

/** Minimal EventSource stand-in; jsdom has none. */
class FakeEventSource {
  static last: FakeEventSource | null = null;
  listeners = new Map<string, ((e: MessageEvent) => void)[]>();
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(readonly url: string) {
    FakeEventSource.last = this;
    queueMicrotask(() => this.onopen?.());
  }
  addEventListener(type: string, fn: (e: MessageEvent) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  emit(type: string, data: unknown) {
    for (const fn of this.listeners.get(type) ?? []) fn({ data: JSON.stringify(data) } as MessageEvent);
  }
  close() {
    this.closed = true;
  }
}

const event: AuditEvent = {
  id: 1,
  ts: new Date().toISOString(),
  kind: "request",
  request_id: "REQ1",
  client_ip: "10.0.0.7",
  host: "api.githubcopilot.com",
  path: "/chat/completions",
  service: "copilot",
  action: "block",
  rule: "secrets",
  reason: "dlp",
  block_mode: "synthetic",
  latency_ms: 4,
  findings: [
    { detector: "aws_access_key", severity: "critical", confidence: 1, segment: "/messages/0/content", preview: "AKIA****EY" },
  ],
};

function renderTraffic() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Traffic />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.stubGlobal("EventSource", FakeEventSource as unknown as typeof EventSource);
});

describe("Traffic", () => {
  it("shows live events and expands one to reveal the masked match", async () => {
    renderTraffic();
    const user = userEvent.setup();

    await waitFor(() => expect(FakeEventSource.last).not.toBeNull());
    FakeEventSource.last!.emit("audit", event);

    expect(await screen.findByText("api.githubcopilot.com")).toBeInTheDocument();
    // Scoped to the feed: "Stopped" is also an option in the outcome filter.
    expect(within(screen.getByRole("list")).getByText("Stopped")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { expanded: false, name: /api.githubcopilot.com/ }));
    expect(await screen.findByText("AKIA****EY")).toBeInTheDocument();
    expect(screen.getByText("/messages/0/content")).toBeInTheDocument();
    expect(screen.getByText("REQ1")).toBeInTheDocument();
  });

  it("warns when the feed fell behind so a gap is not mistaken for quiet", async () => {
    renderTraffic();
    await waitFor(() => expect(FakeEventSource.last).not.toBeNull());
    FakeEventSource.last!.emit("dropped", { dropped: 12 });

    expect(await screen.findByText(/12 events were skipped/)).toBeInTheDocument();
  });

  it("filters live rows by the search box", async () => {
    renderTraffic();
    const user = userEvent.setup();
    await waitFor(() => expect(FakeEventSource.last).not.toBeNull());
    FakeEventSource.last!.emit("audit", event);
    FakeEventSource.last!.emit("audit", { ...event, id: 2, host: "api.openai.com", rule: "", action: "allow" });

    expect(await screen.findByText("api.openai.com")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Search"), "copilot");

    await waitFor(() => expect(screen.queryByText("api.openai.com")).not.toBeInTheDocument());
    expect(screen.getByText("api.githubcopilot.com")).toBeInTheDocument();
  });

  it("queries the history when the live feed is switched off", async () => {
    const events = vi.spyOn(api, "events").mockResolvedValue({ items: [event] });
    renderTraffic();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "History" }));

    await waitFor(() => expect(events).toHaveBeenCalled());
    expect(FakeEventSource.last!.closed).toBe(true);
    expect(await screen.findByText("api.githubcopilot.com")).toBeInTheDocument();
  });
});
