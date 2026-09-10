import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Tester } from "./Tester";
import { api } from "../api/client";
import type { ConfigResponse, TestResponse } from "../api/types";

function renderTester() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Tester />
    </QueryClientProvider>,
  );
}

const config = {
  yaml: "",
  version: "v1",
  loaded_at: new Date().toISOString(),
  source: "startup",
  path: "/etc/aigatekeeper/aigatekeeper.yaml",
  config: {
    version: 1,
    services: [{ name: "openai", hosts: [], extractor: "openai", block_mode: "reject" as const, rules: ["secrets"] }],
    rules: [],
  },
} satisfies ConfigResponse;

const blocked: TestResponse = {
  extraction: {
    extractor: "text",
    stream: false,
    segments: [{ path: "/text", role: "user", text: "my key is AKIAIOSFODNN7REALKEY" }],
  },
  findings: [
    {
      detector: "aws_access_key",
      severity: "critical",
      confidence: 1,
      segment: "/text",
      role: "user",
      preview: "AKIA****EY",
    },
  ],
  decision: { action: "block", rule: "secrets", reason: "dlp", block_mode: "reject", detectors: ["aws_access_key"] },
  service: "openai",
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, "config").mockResolvedValue(config);
});

describe("Tester", () => {
  it("shows the outcome, the match and what the policy read", async () => {
    vi.spyOn(api, "test").mockResolvedValue(blocked);
    renderTester();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Check against the policy" }));

    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    expect(screen.getByText(/Rule secrets matched on aws_access_key/)).toBeInTheDocument();
    expect(screen.getByText("aws_access_key")).toBeInTheDocument();
    expect(screen.getByText("AKIA****EY")).toBeInTheDocument();
    expect(screen.getByText("1 match")).toBeInTheDocument();
    // The prompt text the policy saw is shown so a false positive can be traced.
    expect(screen.getByText("my key is AKIAIOSFODNN7REALKEY")).toBeInTheDocument();
  });

  it("sends the chosen service and the request body when checking a capture", async () => {
    const test = vi.spyOn(api, "test").mockResolvedValue({ ...blocked, decision: { ...blocked.decision, action: "allow" } });
    renderTester();
    const user = userEvent.setup();

    await waitFor(() => expect(screen.getByLabelText("Evaluate as")).toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Request body" }));
    await user.selectOptions(screen.getByLabelText("Evaluate as"), "openai");
    await user.click(screen.getByRole("button", { name: "Check against the policy" }));

    await waitFor(() =>
      expect(test).toHaveBeenCalledWith(expect.objectContaining({ service: "openai", body: expect.stringContaining("messages") })),
    );
    expect(test).not.toHaveBeenCalledWith(expect.objectContaining({ text: expect.anything() }));
  });

  it("reports a failure instead of showing a stale result", async () => {
    vi.spyOn(api, "test").mockRejectedValue(new Error("no policy loaded"));
    renderTester();
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Check against the policy" }));
    expect(await screen.findByText("no policy loaded")).toBeInTheDocument();
    expect(screen.queryByText("Stopped")).not.toBeInTheDocument();
  });
});
