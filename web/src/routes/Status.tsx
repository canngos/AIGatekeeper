import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { Page } from "../components/Layout";
import { Button, Notice, Panel, TextInput, relativeTime } from "../components/primitives";
import { useState } from "react";

export function Status() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["status"], queryFn: api.status, refetchInterval: 15_000 });
  const [message, setMessage] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [testTo, setTestTo] = useState("");
  const [testing, setTesting] = useState(false);

  async function sendTestAlert() {
    setTesting(true);
    setMessage(null);
    try {
      const res = await api.testAlert({ to: testTo ? testTo.split(",").map((s) => s.trim()) : undefined });
      const failed = res.results.filter((r) => r.error);
      setMessage(
        failed.length === 0
          ? { tone: "ok", text: `Test alert delivered through ${res.results.map((r) => r.notifier).join(", ")}.` }
          : { tone: "error", text: failed.map((r) => `${r.notifier}: ${r.error}`).join("; ") },
      );
    } catch (err) {
      setMessage({ tone: "error", text: err instanceof Error ? err.message : "The test failed" });
    } finally {
      setTesting(false);
    }
  }

  async function reload() {
    setMessage(null);
    try {
      const res = await api.reload();
      setMessage({
        tone: "ok",
        text: res.changed
          ? `Reloaded. Now enforcing version ${res.version.slice(0, 12)}.`
          : "The file on disk matches what is already loaded, so nothing changed.",
      });
      await qc.invalidateQueries({ queryKey: ["status"] });
      await qc.invalidateQueries({ queryKey: ["config"] });
    } catch (err) {
      setMessage({ tone: "error", text: err instanceof Error ? err.message : "Reload failed" });
    }
  }

  const s = status.data;
  return (
    <Page
      title="Status"
      description="What this proxy is running and whether anything needs attention."
      actions={
        <>
          <Button onClick={() => void reload()}>Reload from disk</Button>
          <a href="/ca.crt" download>
            <Button>Download CA certificate</Button>
          </a>
        </>
      }
    >
      <div className="grid gap-4">
        {message && <Notice tone={message.tone}>{message.text}</Notice>}
        {s?.reload?.last_error && (
          <Notice tone="error">
            The last attempt to load the configuration failed, so the proxy is still enforcing the previous version.{" "}
            {s.reload.last_error}
          </Notice>
        )}
        {(s?.alerts?.rules ?? 0) > 0 && (
          <Panel title="Test the alert path">
            <p className="mb-3 max-w-[70ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
              Sends a sample alert through the configured destinations so you can confirm the relay works before
              relying on it. Give an address to keep the test off your real distribution list.
            </p>
            <div className="flex flex-wrap items-end gap-3">
              <div className="min-w-[18rem] flex-1">
                <label htmlFor="test-to" className="mb-1 block text-[12.5px] font-medium">
                  Send to
                </label>
                <TextInput id="test-to" value={testTo} onChange={setTestTo} placeholder="you@corp.example" />
              </div>
              <Button onClick={() => void sendTestAlert()} disabled={testing}>
                {testing ? "Sending" : "Send a test alert"}
              </Button>
            </div>
          </Panel>
        )}

        {s?.policy?.monitor && (
          <Notice tone="info">
            Monitor mode is on. Requests that would be stopped are recorded and forwarded anyway. Turn it off in the
            policy once the matches look right.
          </Notice>
        )}

        <div className="grid gap-4 md:grid-cols-2">
          <Panel title="Proxy" flush>
            <Rows
              rows={[
                ["Version", s?.version],
                ["Running for", s ? formatUptime(s.uptime_seconds) : undefined],
                ["Web console", s?.ui_built ? "Built in" : "Not built"],
              ]}
            />
          </Panel>
          <Panel title="Listeners" flush>
            <Rows rows={Object.entries(s?.listeners ?? {}).map(([k, v]) => [k, v] as [string, string])} mono />
          </Panel>
          <Panel title="Policy" flush>
            <Rows
              rows={[
                ["Version", s?.policy?.version.slice(0, 12)],
                ["Loaded", s?.policy ? `${relativeTime(s.policy.loaded_at)} (${s.policy.source})` : undefined],
                ["Services", s?.policy?.services?.toString()],
                ["Rules", s?.policy?.rules?.toString()],
                ["Unlisted destinations", s?.policy?.tunnel_unmatched ? "Tunnelled untouched" : "Refused"],
                ["Monitor mode", s?.policy?.monitor ? "On" : "Off"],
                ["File", s?.reload?.path],
                ["Reloads", s?.reload ? `${s.reload.reloads} applied, ${s.reload.failures} rejected` : undefined],
              ]}
            />
          </Panel>
          <Panel title="Attribution" flush>
            <Rows
              rows={[
                ["Developers sign in to the proxy", s?.identity?.proxy_auth ? "Yes" : "No"],
                ["Workstation names resolved", s?.identity?.reverse_dns ? "Yes" : "No"],
                ["User directory", s?.identity?.directory ? "Loaded" : "Not configured"],
                [
                  "Credentials checked",
                  s?.identity?.proxy_auth_stats
                    ? `${s.identity.proxy_auth_stats.successes ?? 0} accepted, ${s.identity.proxy_auth_stats.failures ?? 0} rejected`
                    : undefined,
                ],
                ["Alert rules", s?.alerts ? String(s.alerts.rules) : "None"],
                ["Alerts raised", s?.alerts ? `${s.alerts.raised} raised, ${s.alerts.suppressed} held by cooldown` : undefined],
                ["Alerts waiting", s?.open_alerts !== undefined ? String(s.open_alerts) : undefined],
              ]}
            />
          </Panel>
          <Panel title="Audit" flush>
            <Rows
              rows={[
                ["Searchable history", s?.history ? "On" : "Off"],
                ["Events stored", s?.history_store?.written?.toLocaleString()],
                ["Store errors", s?.history_store?.errors?.toString()],
                ...(s?.audit_sinks ?? []).map(
                  (sink) =>
                    [
                      `Sink ${sink.name}`,
                      `${sink.written.toLocaleString()} written${sink.dropped > 0 ? `, ${sink.dropped.toLocaleString()} dropped` : ""}`,
                    ] as [string, string],
                ),
              ]}
            />
          </Panel>
        </div>

        {(s?.audit_sinks ?? []).some((sink) => sink.dropped > 0) && (
          <Notice tone="error">
            Some audit events were dropped because a sink could not keep up. Raise its queue size in the configuration,
            or send the log somewhere faster.
          </Notice>
        )}
      </div>
    </Page>
  );
}

function Rows({ rows, mono }: { rows: [string, string | undefined][]; mono?: boolean }) {
  return (
    <dl>
      {rows
        .filter(([, v]) => v !== undefined && v !== "")
        .map(([k, v]) => (
          <div
            key={k}
            className="flex items-baseline justify-between gap-4 border-b px-4 py-1.5 last:border-b-0"
            style={{ borderColor: "var(--rule)" }}
          >
            <dt className="text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
              {k}
            </dt>
            <dd className={`truncate text-[12.5px] ${mono ? "wire" : ""}`}>{v}</dd>
          </div>
        ))}
    </dl>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds} seconds`;
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return `${mins} minutes`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours} hours`;
  return `${Math.floor(hours / 24)} days`;
}
