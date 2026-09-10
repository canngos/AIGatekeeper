import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { StoredAlert, UserSummary } from "../api/types";
import { Page } from "../components/Layout";
import {
  Button,
  Empty,
  Notice,
  Panel,
  Select,
  Severity,
  Tag,
  actionColor,
  relativeTime,
} from "../components/primitives";

const RANGES = [
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];

export function People() {
  const [range, setRange] = useState("7d");
  const users = useQuery({ queryKey: ["users", range], queryFn: () => api.users(range) });
  const alerts = useQuery({ queryKey: ["alerts"], queryFn: () => api.alerts({}), refetchInterval: 30_000 });
  const status = useQuery({ queryKey: ["status"], queryFn: api.status });

  const historyOff = users.error && String(users.error.message).includes("history");
  const attributed = users.data?.attributed ?? false;
  const alertingOff = (status.data?.alerts?.rules ?? 0) === 0;

  return (
    <Page
      title="People"
      description="Who is running into the policy, and who has been told about it."
      actions={
        <Select
          value={range}
          onChange={setRange}
          options={RANGES.map((r) => ({ value: r.value, label: r.label }))}
        />
      }
    >
      {historyOff ? (
        <Notice tone="info">
          The searchable history is turned off, so there is nothing to attribute yet. Set audit.sqlite.enabled to true
          in the configuration.
        </Notice>
      ) : (
        <div className="grid gap-5">
          {!attributed && (
            <Notice tone="info">
              Requests are grouped by workstation, not by person. Turn on identity.proxy_auth so developers sign in to
              the proxy, and these rows become names.
            </Notice>
          )}

          <Panel title="Most findings" flush>
            <UserTable users={users.data?.users ?? []} loading={users.isLoading} />
          </Panel>

          <Panel
            title="Alerts"
            actions={
              alerts.data && alerts.data.open > 0 ? (
                <Tag tone="block">{alerts.data.open} open</Tag>
              ) : undefined
            }
            flush
          >
            {alertingOff ? (
              <Empty title="No alert rules are configured">
                Add a rule under alerts in the configuration to be told when one person repeats violations.
              </Empty>
            ) : (
              <AlertList alerts={alerts.data?.items ?? []} loading={alerts.isLoading} />
            )}
          </Panel>
        </div>
      )}
    </Page>
  );
}

function UserTable({ users, loading }: { users: UserSummary[]; loading: boolean }) {
  if (loading) return <div className="h-40 animate-pulse" style={{ background: "var(--surface-sunken)" }} />;
  if (users.length === 0) {
    return <Empty title="Nothing to show yet">Requests appear here once developers start using the proxy.</Empty>;
  }
  return (
    <table className="w-full text-[12.5px]">
      <thead>
        <tr style={{ color: "var(--ink-faint)" }}>
          <th className="px-4 py-1.5 text-left font-medium">Who</th>
          <th className="px-4 py-1.5 text-right font-medium">Requests</th>
          <th className="px-4 py-1.5 text-right font-medium">Stopped</th>
          <th className="px-4 py-1.5 text-right font-medium">Flagged</th>
          <th className="px-4 py-1.5 text-right font-medium">Last seen</th>
        </tr>
      </thead>
      <tbody>
        {users.map((u, i) => (
          <tr key={i} className="border-t" style={{ borderColor: "var(--rule)" }}>
            <td className="px-4 py-1.5">
              <span className="wire">{u.user || u.device || u.client_ip}</span>
              {u.user && u.device && (
                <span className="ml-2 text-[11px]" style={{ color: "var(--ink-faint)" }}>
                  {u.device}
                </span>
              )}
              {!u.user && (
                <span className="ml-2 text-[11px]" style={{ color: "var(--ink-faint)" }}>
                  {u.device ? "workstation" : "address"}
                </span>
              )}
            </td>
            <td className="tnum px-4 py-1.5 text-right">{u.requests.toLocaleString()}</td>
            <td className="tnum px-4 py-1.5 text-right" style={{ color: u.blocked > 0 ? actionColor("block") : undefined }}>
              {u.blocked.toLocaleString()}
            </td>
            <td className="tnum px-4 py-1.5 text-right" style={{ color: u.flagged > 0 ? actionColor("monitor") : undefined }}>
              {u.flagged.toLocaleString()}
            </td>
            <td className="px-4 py-1.5 text-right" style={{ color: "var(--ink-muted)" }}>
              {relativeTime(u.last_seen)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function AlertList({ alerts, loading }: { alerts: StoredAlert[]; loading: boolean }) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<number | null>(null);
  const [busy, setBusy] = useState<number | null>(null);

  if (loading) return <div className="h-32 animate-pulse" style={{ background: "var(--surface-sunken)" }} />;
  if (alerts.length === 0) {
    return <Empty title="No alerts raised">Nobody has crossed an alert threshold in the recorded history.</Empty>;
  }

  async function acknowledge(id: number) {
    setBusy(id);
    try {
      await api.acknowledgeAlert(id);
      await qc.invalidateQueries({ queryKey: ["alerts"] });
      await qc.invalidateQueries({ queryKey: ["status"] });
    } finally {
      setBusy(null);
    }
  }

  return (
    <ul>
      {alerts.map((a) => {
        const open = expanded === a.id;
        const who = a.user || a.device || a.client_ip || a.group_key;
        return (
          <li key={a.id} className="border-b last:border-b-0" style={{ borderColor: "var(--rule)" }}>
            <div className="flex items-center gap-3 px-4 py-2">
              <button
                onClick={() => setExpanded(open ? null : a.id)}
                className="flex min-w-0 flex-1 items-baseline gap-3 text-left"
                aria-expanded={open}
              >
                <span
                  aria-hidden
                  style={{ width: 8, height: 8, background: a.status === "open" ? "var(--block)" : "var(--ink-faint)" }}
                />
                <span className="wire truncate">{who}</span>
                <span className="text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
                  {a.count} in {a.window}
                </span>
                <span className="text-[12px]" style={{ color: "var(--ink-faint)" }}>
                  {a.rule_id}
                </span>
              </button>
              <Severity level={a.severity || "high"} />
              <span className="w-[74px] shrink-0 text-right text-[12px]" style={{ color: "var(--ink-faint)" }}>
                {relativeTime(a.ts)}
              </span>
              {a.status === "open" ? (
                <Button onClick={() => void acknowledge(a.id)} disabled={busy === a.id}>
                  {busy === a.id ? "Saving" : "Acknowledge"}
                </Button>
              ) : (
                <span className="w-[92px] text-right text-[12px]" style={{ color: "var(--ink-faint)" }}>
                  Acknowledged
                </span>
              )}
            </div>

            {open && (
              <div className="px-4 pb-3 pl-[27px]">
                {a.detail?.notify_errors && a.detail.notify_errors.length > 0 && (
                  <div className="mb-2">
                    <Notice tone="error">
                      {(a.detail.notified?.length ?? 0) > 0
                        ? "Some destinations could not be reached. "
                        : "This alert was recorded but reached nobody. "}
                      {a.detail.notify_errors.join("; ")}
                    </Notice>
                  </div>
                )}
                <dl className="mb-2 flex flex-wrap gap-x-6 gap-y-1 text-[12px]" style={{ color: "var(--ink-muted)" }}>
                  <Meta label="Grouped by" value={a.group_by} />
                  <Meta label="Found" value={a.detail?.detectors?.join(", ")} />
                  <Meta label="Services" value={a.detail?.services?.join(", ")} />
                  <Meta label="Told" value={summariseNotified(a.detail?.notified)} />
                  {a.acknowledged_by && <Meta label="Acknowledged by" value={a.acknowledged_by} />}
                </dl>
                {a.detail?.events && a.detail.events.length > 0 && (
                  <table className="w-full text-[12px]">
                    <thead>
                      <tr style={{ color: "var(--ink-faint)" }}>
                        <th className="py-1 pr-4 text-left font-medium">When</th>
                        <th className="py-1 pr-4 text-left font-medium">Destination</th>
                        <th className="py-1 pr-4 text-left font-medium">What was found</th>
                        <th className="py-1 text-left font-medium">Match</th>
                      </tr>
                    </thead>
                    <tbody>
                      {a.detail.events.map((e, i) => (
                        <tr key={i} className="border-t" style={{ borderColor: "var(--rule)" }}>
                          <td className="wire py-1 pr-4" style={{ color: "var(--ink-faint)" }}>
                            {new Date(e.ts).toLocaleTimeString(undefined, { hour12: false })}
                          </td>
                          <td className="wire py-1 pr-4 truncate">
                            {e.host}
                            <span style={{ color: "var(--ink-faint)" }}>{e.path}</span>
                          </td>
                          <td className="wire py-1 pr-4">{e.detectors.join(", ")}</td>
                          <td className="wire py-1">{e.previews.join(" ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** One destination used twice reads as "email x2" rather than "email, email". */
function summariseNotified(notified?: string[]): string {
  if (!notified || notified.length === 0) return "nobody";
  const counts = new Map<string, number>();
  for (const n of notified) counts.set(n, (counts.get(n) ?? 0) + 1);
  return [...counts].map(([name, n]) => (n > 1 ? `${name} x${n}` : name)).join(", ");
}

function Meta({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div className="flex gap-1.5">
      <dt>{label}</dt>
      <dd style={{ color: "var(--ink)" }}>{value}</dd>
    </div>
  );
}
