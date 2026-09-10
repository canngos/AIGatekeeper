import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api/client";
import type { Bucket, Count, Summary } from "../api/types";
import { Page } from "../components/Layout";
import { Empty, Notice, Panel, actionColor, actionLabel } from "../components/primitives";

const RANGES = [
  { value: "1h", label: "Last hour" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
];

export function Overview() {
  const [range, setRange] = useState("24h");
  const summary = useQuery({
    queryKey: ["summary", range],
    queryFn: () => api.summary(range),
    refetchInterval: 30_000,
  });
  const series = useQuery({
    queryKey: ["timeseries", range],
    queryFn: () => api.timeseries(range, "action"),
    refetchInterval: 30_000,
  });

  const unavailable = summary.error && String(summary.error.message).includes("history");

  return (
    <Page
      title="Overview"
      description="What developer traffic did at the gate, and which rules acted on it."
      actions={
        <div className="flex border" style={{ borderColor: "var(--rule-strong)", background: "var(--surface)" }}>
          {RANGES.map((r) => (
            <button
              key={r.value}
              onClick={() => setRange(r.value)}
              className="px-2.5 py-1 text-[12.5px]"
              style={{
                background: range === r.value ? "var(--accent-soft)" : "transparent",
                color: range === r.value ? "var(--ink)" : "var(--ink-muted)",
                fontWeight: range === r.value ? 600 : 400,
              }}
            >
              {r.label}
            </button>
          ))}
        </div>
      }
    >
      {unavailable ? (
        <Notice tone="info">
          The searchable history is turned off, so there are no aggregates to show. Set audit.sqlite.enabled to true in
          the configuration to record events for this console. Live traffic still appears under Traffic, and JSON logs
          keep going to stdout.
        </Notice>
      ) : (
        <div className="grid gap-5">
          <FlowBand summary={summary.data} loading={summary.isLoading} />
          <Panel title="Requests over time">
            <TrafficChart buckets={series.data?.series ?? []} loading={series.isLoading} />
          </Panel>
          <div className="grid gap-5 md:grid-cols-3">
            <Panel title="Rules that acted" flush>
              <Breakdown rows={summary.data?.by_rule} empty="No rule has fired in this window." />
            </Panel>
            <Panel title="What was found" flush>
              <Breakdown rows={summary.data?.by_detector} empty="No detector has matched in this window." mono />
            </Panel>
            <Panel title="Busiest services" flush>
              <Breakdown rows={summary.data?.by_service} empty="No inspected traffic in this window." />
            </Panel>
          </div>
          <div className="grid gap-5 md:grid-cols-2">
            <Panel title="Workstations with the most findings" flush>
              <Breakdown rows={summary.data?.top_clients} empty="Nothing flagged or stopped in this window." mono />
            </Panel>
            <Panel title="Destinations" flush>
              <Breakdown rows={summary.data?.top_hosts} empty="No inspected traffic in this window." mono />
            </Panel>
          </div>
        </div>
      )}
    </Page>
  );
}

/**
 * The hero: one continuous band showing the proportion of requests that were
 * forwarded, flagged and stopped. The picture the security team actually
 * wants is "what got through the gate", not a headline number.
 */
function FlowBand({ summary, loading }: { summary?: Summary; loading: boolean }) {
  const counts = new Map((summary?.by_action ?? []).map((c) => [c.key, c.count]));
  const allow = counts.get("allow") ?? 0;
  const monitor = counts.get("monitor") ?? 0;
  const block = counts.get("block") ?? 0;
  const total = allow + monitor + block;

  return (
    <Panel>
      {loading ? (
        <div className="h-[74px] animate-pulse" style={{ background: "var(--surface-sunken)" }} />
      ) : total === 0 ? (
        <Empty title="No inspected requests in this window">
          Once a workstation sends a prompt through the proxy it appears here within seconds.
        </Empty>
      ) : (
        <>
          <div className="flex h-9 w-full overflow-hidden" style={{ background: "var(--surface-sunken)" }}>
            {(
              [
                ["allow", allow],
                ["monitor", monitor],
                ["block", block],
              ] as const
            ).map(([action, n]) =>
              n === 0 ? null : (
                <div
                  key={action}
                  style={{ width: `${(n / total) * 100}%`, background: actionColor(action) }}
                  title={`${actionLabel(action)}: ${n.toLocaleString()}`}
                />
              ),
            )}
          </div>
          <dl className="mt-3 flex flex-wrap gap-x-8 gap-y-2">
            {(
              [
                ["allow", allow],
                ["monitor", monitor],
                ["block", block],
              ] as const
            ).map(([action, n]) => (
              <div key={action} className="flex items-baseline gap-2">
                <span style={{ width: 8, height: 8, background: actionColor(action) }} aria-hidden />
                <dt className="text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
                  {actionLabel(action)}
                </dt>
                <dd className="tnum text-[17px] font-semibold tracking-tight">{n.toLocaleString()}</dd>
              </div>
            ))}
            {summary && summary.tunnel_events > 0 && (
              <div className="flex items-baseline gap-2">
                <dt className="text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
                  Passed through untouched
                </dt>
                <dd className="tnum text-[17px] font-semibold tracking-tight">
                  {summary.tunnel_events.toLocaleString()}
                </dd>
              </div>
            )}
          </dl>
        </>
      )}
    </Panel>
  );
}

function TrafficChart({ buckets, loading }: { buckets: Bucket[]; loading: boolean }) {
  if (loading) return <div className="h-[200px] animate-pulse" style={{ background: "var(--surface-sunken)" }} />;
  if (buckets.length === 0) return <Empty title="Nothing recorded in this window" />;

  const byTime = new Map<string, { ts: string; allow: number; monitor: number; block: number }>();
  for (const b of buckets) {
    const row = byTime.get(b.ts) ?? { ts: b.ts, allow: 0, monitor: 0, block: 0 };
    if (b.group === "allow" || b.group === "monitor" || b.group === "block") row[b.group] += b.count;
    byTime.set(b.ts, row);
  }
  const data = [...byTime.values()].sort((a, b) => a.ts.localeCompare(b.ts));

  // Counts per bucket are discrete, so they are drawn as bars. An area
  // chart would interpolate between buckets and imply traffic that a quiet
  // period did not have.
  return (
    <div style={{ height: 200 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -18 }} barCategoryGap="18%">
          <CartesianGrid stroke="var(--rule)" vertical={false} />
          <XAxis
            dataKey="ts"
            tickFormatter={(v: string) => new Date(v).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
            tick={{ fill: "var(--ink-faint)", fontSize: 11 }}
            stroke="var(--rule)"
            minTickGap={40}
          />
          <YAxis tick={{ fill: "var(--ink-faint)", fontSize: 11 }} stroke="var(--rule)" allowDecimals={false} width={44} />
          <Tooltip
            cursor={{ fill: "var(--accent-soft)", fillOpacity: 0.5 }}
            contentStyle={{
              background: "var(--surface)",
              border: "1px solid var(--rule-strong)",
              borderRadius: 0,
              fontSize: 12,
              color: "var(--ink)",
            }}
            labelFormatter={(v: string) => new Date(v).toLocaleString()}
            formatter={(value: number, name: string) => [value, actionLabel(name)]}
          />
          <Bar dataKey="allow" stackId="1" fill="var(--allow)" maxBarSize={48} />
          <Bar dataKey="monitor" stackId="1" fill="var(--monitor)" maxBarSize={48} />
          <Bar dataKey="block" stackId="1" fill="var(--block)" maxBarSize={48} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function Breakdown({ rows, empty, mono }: { rows?: Count[] | null; empty: string; mono?: boolean }) {
  if (!rows || rows.length === 0) return <Empty title={empty} />;
  const max = Math.max(...rows.map((r) => r.count));
  return (
    <ul>
      {rows.slice(0, 8).map((r) => (
        <li
          key={r.key}
          className="relative flex items-center justify-between gap-3 border-b px-4 py-1.5 last:border-b-0"
          style={{ borderColor: "var(--rule)" }}
        >
          <span
            aria-hidden
            className="absolute inset-y-0 left-0"
            style={{ width: `${(r.count / max) * 100}%`, background: "var(--accent-soft)", opacity: 0.6 }}
          />
          <span className={`relative truncate text-[12.5px] ${mono ? "wire" : ""}`}>{r.key}</span>
          <span className="tnum relative text-[12.5px] font-medium">{r.count.toLocaleString()}</span>
        </li>
      ))}
    </ul>
  );
}
