import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Policy } from "./Policy";
import { api } from "../api/client";
import type { ConfigResponse, DetectorInfo } from "../api/types";

// CodeMirror measures text, which jsdom cannot do. The file view is a text
// box for the purposes of these tests.
vi.mock("@uiw/react-codemirror", () => ({
  default: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <textarea aria-label="Policy file" value={value} onChange={(e) => onChange(e.target.value)} />
  ),
}));

function renderPolicy() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Policy />
    </QueryClientProvider>,
  );
}

const detectors: DetectorInfo[] = [
  {
    id: "access_keys",
    name: "Cloud access key IDs",
    group: "Keys and tokens",
    description: "Access key identifiers matched by vendor prefix.",
    severity: "critical",
    options: [
      {
        name: "prefixes",
        label: "Prefixes",
        type: "prefix_list",
        default: [
          { prefix: "AKIA", length: 16, note: "AWS long-term" },
          { prefix: "LTAI", note: "Alibaba Cloud" },
        ],
        description: "A key is the prefix followed by random characters.",
      },
      { name: "min_length", label: "Shortest key", type: "number", default: 16, description: "Characters after the prefix." },
    ],
  },
  {
    id: "aws_access_key",
    name: "AWS access key IDs",
    group: "Keys and tokens",
    description: "AWS access key IDs only.",
    severity: "critical",
    deprecated: true,
    replaced_by: "access_keys",
  },
  {
    id: "credit_card",
    name: "Payment card numbers",
    group: "Personal data",
    description: "Luhn-valid card numbers.",
    severity: "high",
  },
];

const config: ConfigResponse = {
  yaml: "version: 1\n# a comment worth keeping\n",
  version: "v1",
  loaded_at: new Date().toISOString(),
  source: "startup",
  path: "/etc/aigatekeeper/aigatekeeper.yaml",
  config: {
    version: 1,
    mode: { monitor: true },
    default_action: "block",
    services: [
      { name: "copilot", hosts: ["^api\\.githubcopilot\\.com$", "^.*\\.githubcopilot\\.com$"], extractor: "copilot", block_mode: "synthetic", rules: ["secrets"] },
      { name: "openai", hosts: ["^api\.openai\.com$"], extractor: "openai", block_mode: "reject", rules: ["secrets"] },
    ],
    rules: [{ id: "secrets", severity: "critical", action: "block", detectors: ["access_keys"] }],
  },
};

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(api, "config").mockResolvedValue(config);
  vi.spyOn(api, "detectors").mockResolvedValue({ detectors, extractors: ["copilot", "openai", "generic"] });
});

function section(name: string) {
  return within(screen.getByRole("region", { name }));
}

async function openRule() {
  const user = userEvent.setup();
  renderPolicy();
  await screen.findByRole("region", { name: "What to look for" });
  await user.click(section("What to look for").getByRole("button", { name: /secrets/ }));
  return user;
}

describe("Policy", () => {
  it("shows watch-only enforcement as the warning it is", async () => {
    renderPolicy();
    await screen.findByText("Enforcement");
    expect(screen.getByRole("radio", { name: "Watch only" })).toBeChecked();
    expect(screen.getByText(/Nothing is being stopped/)).toBeInTheDocument();
  });

  it("turning blocking on marks the policy unsaved", async () => {
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByText("Enforcement");
    expect(screen.queryByText(/Unsaved changes/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: "Blocking" }));

    expect(screen.getByText(/Unsaved changes/)).toBeInTheDocument();
    expect(screen.getByText(/stopped before they reach the model/)).toBeInTheDocument();
  });

  it("lists services and rules collapsed, and opens one at a time", async () => {
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByRole("region", { name: "What gets inspected" });
    const services = section("What gets inspected");

    // Collapsed: the summary is visible, the form is not.
    expect(services.getByText(/api.githubcopilot.com and 1 more/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Host names")).not.toBeInTheDocument();

    await user.click(services.getByRole("button", { name: /copilot/ }));
    expect(screen.getByLabelText("Host names")).toBeInTheDocument();

    await user.click(services.getByRole("button", { name: /copilot/ }));
    expect(screen.queryByLabelText("Host names")).not.toBeInTheDocument();
  });

  it("offers detectors by name, grouped, and hides retired ones the rule does not use", async () => {
    await openRule();
    expect(screen.getByText("Keys and tokens")).toBeInTheDocument();
    expect(screen.getByText("Personal data")).toBeInTheDocument();
    expect(screen.getByLabelText("Cloud access key IDs")).toBeChecked();
    expect(screen.getByLabelText("Payment card numbers")).not.toBeChecked();
    expect(screen.queryByLabelText("AWS access key IDs")).not.toBeInTheDocument();
  });

  it("shows a retired detector the rule still uses, with a way off it", async () => {
    vi.spyOn(api, "config").mockResolvedValue({
      ...config,
      config: { ...config.config, rules: [{ id: "secrets", severity: "critical", detectors: ["aws_access_key"] }] },
    });
    const user = await openRule();
    expect(screen.getByLabelText("AWS access key IDs")).toBeChecked();

    await user.click(screen.getByRole("button", { name: /Switch to access_keys/ }));

    expect(screen.getByLabelText("Cloud access key IDs")).toBeChecked();
    expect(screen.queryByLabelText("AWS access key IDs")).not.toBeInTheDocument();
  });

  it("edits access key prefixes and writes the whole list into the rule", async () => {
    const user = await openRule();
    await user.click(screen.getByRole("button", { name: "Settings" }));

    // The shipped defaults are shown, and marked as not yet owned.
    expect(screen.getByText(/Defaults. Editing makes a copy you own./)).toBeInTheDocument();
    expect(screen.getByLabelText("Prefix 1")).toHaveValue("AKIA");
    expect(screen.getByLabelText("Key length 2")).toHaveValue(null); // blank means any

    await user.click(screen.getByRole("button", { name: "Add prefix" }));
    await user.type(screen.getByLabelText("Prefix 3"), "CORP");
    await user.type(screen.getByLabelText("Key length 3"), "24");

    expect(screen.getByText(/Unsaved changes/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reset to defaults" })).toBeInTheDocument();

    const applied = vi.spyOn(api, "applyConfig").mockResolvedValue({ applied: true, version: "v2", loaded_at: new Date().toISOString() });
    await user.click(screen.getByRole("button", { name: "Apply changes" }));

    await waitFor(() => expect(applied).toHaveBeenCalled());
    const sent = applied.mock.calls[0][0] as { config: { rules: { options?: Record<string, Record<string, unknown>> }[] } };
    const prefixes = sent.config.rules[0].options?.access_keys?.prefixes as { prefix: string; length?: number }[];
    expect(prefixes).toEqual([
      { prefix: "AKIA", length: 16, note: "AWS long-term" },
      { prefix: "LTAI", note: "Alibaba Cloud" },
      { prefix: "CORP", length: 24 },
    ]);
  });

  it("resetting prefixes drops the option so the defaults apply again", async () => {
    const user = await openRule();
    await user.click(screen.getByRole("button", { name: "Settings" }));
    await user.clear(screen.getByLabelText("Prefix 1"));
    await user.type(screen.getByLabelText("Prefix 1"), "CORP");

    await user.click(screen.getByRole("button", { name: "Reset to defaults" }));

    expect(screen.getByLabelText("Prefix 1")).toHaveValue("AKIA");
    expect(screen.getByText(/Defaults. Editing makes a copy you own./)).toBeInTheDocument();
  });

  it("switches a destination off without removing it", async () => {
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByRole("region", { name: "What gets inspected" });
    const row = within(screen.getByRole("group", { name: "openai" }));

    expect(row.getByLabelText("Active")).toBeChecked();
    expect(screen.getByText("2")).toBeInTheDocument(); // both inspected

    await user.click(row.getByLabelText("Active"));

    expect(row.getByLabelText("Active")).not.toBeChecked();
    expect(row.getByText(/Not inspected. Prompts sent here pass through unread./)).toBeInTheDocument();
    expect(screen.getByText("1 off")).toBeInTheDocument();
    // The destination is still listed, with everything it needs to come back.
    expect(screen.getByRole("group", { name: "openai" })).toBeInTheDocument();

    const applied = vi.spyOn(api, "applyConfig").mockResolvedValue({ applied: true, version: "v2", loaded_at: new Date().toISOString() });
    await user.click(screen.getByRole("button", { name: "Apply changes" }));
    await waitFor(() => expect(applied).toHaveBeenCalled());
    const sent = applied.mock.calls[0][0] as { config: { services: { name: string; enabled?: boolean; hosts: string[] }[] } };
    expect(sent.config.services[1]).toMatchObject({ name: "openai", enabled: false, hosts: ["^api\.openai\.com$"] });
    expect(sent.config.services[0].enabled).toBeUndefined();
  });

  it("warns that a switched-off destination is refused when unlisted hosts are not allowed", async () => {
    vi.spyOn(api, "config").mockResolvedValue({
      ...config,
      config: { ...config.config, tunnel_unmatched: false },
    });
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByRole("region", { name: "What gets inspected" });
    const row = within(screen.getByRole("group", { name: "openai" }));

    await user.click(row.getByLabelText("Active"));

    expect(row.getByText(/refused: unlisted destinations are not allowed/)).toBeInTheDocument();
  });

  it("switching a destination back on removes the line rather than writing enabled: true", async () => {
    vi.spyOn(api, "config").mockResolvedValue({
      ...config,
      config: {
        ...config.config,
        services: [{ ...config.config.services[0] }, { ...config.config.services[1], enabled: false }],
      },
    });
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByRole("region", { name: "What gets inspected" });
    const row = within(screen.getByRole("group", { name: "openai" }));
    expect(row.getByLabelText("Active")).not.toBeChecked();

    await user.click(row.getByLabelText("Active"));

    const applied = vi.spyOn(api, "applyConfig").mockResolvedValue({ applied: true, version: "v2", loaded_at: new Date().toISOString() });
    await user.click(screen.getByRole("button", { name: "Apply changes" }));
    await waitFor(() => expect(applied).toHaveBeenCalled());
    const sent = applied.mock.calls[0][0] as { config: { services: { enabled?: boolean }[] } };
    expect("enabled" in sent.config.services[1]).toBe(false);
  });

  it("switching to the file view keeps comments when nothing was edited", async () => {
    const user = userEvent.setup();
    const validate = vi.spyOn(api, "validateConfig");
    renderPolicy();
    await screen.findByRole("region", { name: "What gets inspected" });

    await user.click(screen.getByRole("button", { name: "File" }));

    expect(validate).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Policy file")).toHaveValue(config.yaml);
  });

  it("switching to the file view after an edit carries the edit across", async () => {
    const user = userEvent.setup();
    const validate = vi.spyOn(api, "validateConfig").mockResolvedValue({
      ok: true,
      errors: [],
      yaml: "version: 1\nmode:\n  monitor: false\n",
      config: config.config,
      version: "v1",
    });
    renderPolicy();
    await screen.findByText("Enforcement");
    await user.click(screen.getByRole("radio", { name: "Blocking" }));

    await user.click(screen.getByRole("button", { name: "File" }));

    await waitFor(() => expect(validate).toHaveBeenCalledWith({ config: expect.objectContaining({ mode: { monitor: false } }) }));
    expect(screen.getByText(/Comments in the sections you edited are gone/)).toBeInTheDocument();
  });

  it("refuses to leave the file view while the file is broken", async () => {
    const user = userEvent.setup();
    renderPolicy();
    await screen.findByRole("region", { name: "What gets inspected" });
    await user.click(screen.getByRole("button", { name: "File" }));

    vi.spyOn(api, "validateConfig").mockResolvedValue({
      ok: false,
      errors: [{ path: "services[0].hosts", message: "invalid regular expression" }],
      yaml: "broken",
    });
    await user.type(screen.getByLabelText("Policy file"), "x");
    await user.click(screen.getByRole("button", { name: "Forms" }));

    await waitFor(() => expect(screen.getByText(/The file has problems/)).toBeInTheDocument());
    const problems = screen.getByText("services[0].hosts").closest("li")!;
    expect(within(problems).getByText("invalid regular expression")).toBeInTheDocument();
  });
});
