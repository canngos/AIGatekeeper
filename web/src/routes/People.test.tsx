import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { People } from "./People";
import { api } from "../api/client";
import type { AlertsResponse, Status, UsersResponse } from "../api/types";

function renderPeople() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <People />
    </QueryClientProvider>,
  );
}

const users: UsersResponse = {
  from: new Date().toISOString(),
  to: new Date().toISOString(),
  attributed: true,
  users: [
    { user: "alice", device: "laptop-alice", requests: 42, blocked: 5, flagged: 2, last_seen: new Date().toISOString() },
    { device: "kiosk-3", requests: 9, blocked: 0, flagged: 1, last_seen: new Date().toISOString() },
  ],
};

const alerts: AlertsResponse = {
  open: 1,
  rules: ["repeat-offender"],
  items: [
    {
      id: 7,
      ts: new Date().toISOString(),
      rule_id: "repeat-offender",
      group_key: "alice",
      group_by: "user",
      user: "alice",
      device: "laptop-alice",
      count: 3,
      window: "24h0m0s",
      since: new Date().toISOString(),
      severity: "critical",
      status: "open",
      detail: {
        detectors: ["aws_access_key"],
        services: ["openai"],
        notified: ["email"],
        events: [
          {
            ts: new Date().toISOString(),
            request_id: "R1",
            service: "openai",
            host: "api.openai.com",
            path: "/v1/chat/completions",
            action: "block",
            rule: "secrets",
            detectors: ["aws_access_key"],
            previews: ["AKIA****EY"],
          },
        ],
      },
    },
  ],
};

const status = { version: "test", uptime_seconds: 1, listeners: {}, ui_built: true, history: true, alerts: { rules: 1, raised: 1, suppressed: 0 } } as Status;

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, "status").mockResolvedValue(status);
});

describe("People", () => {
  it("lists who is running into the policy", async () => {
    vi.spyOn(api, "users").mockResolvedValue(users);
    vi.spyOn(api, "alerts").mockResolvedValue(alerts);
    renderPeople();

    // "alice" also names the alert below, so scope to the table.
    const table = within(await screen.findByRole("table"));
    const row = table.getByText("alice").closest("tr")!;
    expect(within(row).getByText("42")).toBeInTheDocument();
    expect(within(row).getByText("5")).toBeInTheDocument();
    // A workstation with no signed-in user is labelled as such.
    expect(screen.getByText("kiosk-3")).toBeInTheDocument();
    expect(screen.getByText("workstation")).toBeInTheDocument();
  });

  it("says when requests are grouped by machine rather than person", async () => {
    vi.spyOn(api, "users").mockResolvedValue({ ...users, attributed: false });
    vi.spyOn(api, "alerts").mockResolvedValue(alerts);
    renderPeople();
    expect(await screen.findByText(/grouped by workstation, not by person/)).toBeInTheDocument();
  });

  it("expands an alert to show the masked matches and acknowledges it", async () => {
    vi.spyOn(api, "users").mockResolvedValue(users);
    vi.spyOn(api, "alerts").mockResolvedValue(alerts);
    const ack = vi.spyOn(api, "acknowledgeAlert").mockResolvedValue({ acknowledged: true });
    renderPeople();
    const user = userEvent.setup();

    expect(await screen.findByText("1 open")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { expanded: false, name: /alice/ }));

    expect(await screen.findByText("AKIA****EY")).toBeInTheDocument();
    expect(screen.getByText("api.openai.com")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Acknowledge" }));
    await waitFor(() => expect(ack).toHaveBeenCalledWith(7));
  });

  it("explains that alerting is off when no rules exist", async () => {
    vi.spyOn(api, "users").mockResolvedValue(users);
    vi.spyOn(api, "alerts").mockResolvedValue({ ...alerts, items: [], open: 0, rules: [] });
    vi.spyOn(api, "status").mockResolvedValue({ ...status, alerts: { rules: 0, raised: 0, suppressed: 0 } });
    renderPeople();
    expect(await screen.findByText("No alert rules are configured")).toBeInTheDocument();
  });
});

describe("alert delivery reporting", () => {
  it("distinguishes a partial delivery failure from reaching nobody", async () => {
    vi.spyOn(api, "users").mockResolvedValue(users);
    const partial = structuredClone(alerts);
    partial.items[0].detail!.notified = ["email", "email"];
    partial.items[0].detail!.notify_errors = ["webhook:soc: webhook returned 501"];
    vi.spyOn(api, "alerts").mockResolvedValue(partial);
    renderPeople();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { expanded: false, name: /alice/ }));
    expect(await screen.findByText(/Some destinations could not be reached/)).toBeInTheDocument();
    // Repeated destinations are counted rather than listed twice.
    expect(screen.getByText("email x2")).toBeInTheDocument();
  });

  it("says an alert reached nobody when every destination failed", async () => {
    vi.spyOn(api, "users").mockResolvedValue(users);
    const failed = structuredClone(alerts);
    failed.items[0].detail!.notified = [];
    failed.items[0].detail!.notify_errors = ["email: connect refused"];
    vi.spyOn(api, "alerts").mockResolvedValue(failed);
    renderPeople();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { expanded: false, name: /alice/ }));
    expect(await screen.findByText(/reached nobody/)).toBeInTheDocument();
    expect(screen.getByText("nobody")).toBeInTheDocument();
  });
});
