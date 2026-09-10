import { useMemo, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useLiveFeed } from "../api/sse";
import type { AuditEvent } from "../api/types";
import { Page } from "../components/Layout";
import {
  Button,
  DecisionMark,
  Empty,
  Notice,
  Select,
  Severity,
  TextInput,
  actionColor,
  actionLabel,
  clockTime,
  relativeTime,
} from "../components/primitives";

interface Filters {
  q: string;
  service: string;
  action: string;
  rule: string;
}

const EMPTY: Filters = { q: "", service: "", action: "", rule: "" };

export function Traffic() {
  const [live, setLive] = useState(true);
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const feed = useLiveFeed(live, 200, { service: filters.service, action: filters.action, kind: "request" });

  const history = useInfiniteQuery({
    queryKey: ["events", filters],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) =>
      api.events({
        // Only inspected requests belong here; start-up and reload events
        // are lifecycle records and live on the Status page.
        kind: "request",
        q: filters.q || undefined,
        service: filters.service || undefined,
        action: filters.action || undefined,
        rule: filters.rule || undefined,
        cursor: pageParam,
        limit: 100,
      }),
    getNextPageParam: (last) => last.next_cursor,
    enabled: !live,
  });

  const historyEvents = useMemo(
    () => (history.data?.pages ?? []).flatMap((p) => p.items),
    [history.data],
  );
  const rows = live ? feed.events : historyEvents;
  const historyOff = history.error && String(history.error.message).includes("history");
  const filtered = live ? rows.filter((e) => matchesText(e, filters.q) && matchesRule(e, filters.rule)) : rows;

  return (
    <Page
      title="Traffic"
      description="Every request the proxy inspected, newest first. Rows expand to show what was found and where."
      actions={
        <>
          <Button variant={live ? "primary" : "default"} onClick={() => setLive(true)}>
            Live
          </Button>
          <Button variant={live ? "default" : "primary"} onClick={() => setLive(false)}>
            History
          </Button>
        </>
      }
    >
      <div className="grid gap-4">
        <FilterBar filters={filters} onChange={setFilters} live={live} />

        {live && (
          <div className="flex items-center gap-3 text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
            <span className="flex items-center gap-1.5">
              <span
                aria-hidden
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: "50%",
                  background: feed.connected ? "var(--allow)" : "var(--ink-faint)",
                }}
              />
              {feed.connected ? "Connected" : "Reconnecting"}
            </span>
            <span className="tnum">{feed.events.length} received</span>
            {feed.events.length > 0 && (
              <button className="underline underline-offset-2" onClick={feed.clear}>
                Clear
              </button>
            )}
          </div>
        )}

        {feed.dropped > 0 && (
          <Notice tone="error">
            {feed.dropped.toLocaleString()} events were skipped because this feed fell behind. Switch to History for a
            complete record.
          </Notice>
        )}

        {historyOff && !live && (
          <Notice tone="info">
            The searchable history is turned off. Set audit.sqlite.enabled to true in the configuration to keep a
            record here; the live view works either way.
          </Notice>
        )}

        <div className="border" style={{ background: "var(--surface)", borderColor: "var(--rule)" }}>
          {filtered.length === 0 ? (
            <Empty title={live ? "Waiting for traffic" : "No matching requests"}>
              {live
                ? "Requests appear the moment a workstation sends one through the proxy."
                : "Widen the filters or pick a different time window."}
            </Empty>
          ) : (
            <ol>
              {filtered.map((e, i) => (
                <EventRow
                  key={e.id ?? `${e.request_id}-${e.ts}-${i}`}
                  event={e}
                  fresh={live && i === 0}
                  expanded={selected === e}
                  onToggle={() => setSelected(selected === e ? null : e)}
                />
              ))}
            </ol>
          )}
        </div>

        {!live && history.hasNextPage && (
          <div>
            <Button onClick={() => void history.fetchNextPage()} disabled={history.isFetchingNextPage}>
              {history.isFetchingNextPage ? "Loading" : "Load older requests"}
            </Button>
          </div>
        )}
      </div>
    </Page>
  );
}

function matchesText(e: AuditEvent, q: string): boolean {
  if (!q) return true;
  const needle = q.toLowerCase();
  return [e.host, e.path, e.client_ip, e.rule, e.request_id, e.user]
    .filter(Boolean)
    .some((v) => String(v).toLowerCase().includes(needle));
}

function matchesRule(e: AuditEvent, rule: string): boolean {
  return !rule || e.rule === rule;
}

function FilterBar({
  filters,
  onChange,
  live,
}: {
  filters: Filters;
  onChange: (f: Filters) => void;
  live: boolean;
}) {
  const dirty = JSON.stringify(filters) !== JSON.stringify(EMPTY);
  return (
    <div
      className="flex flex-wrap items-end gap-3 border p-3"
      style={{ background: "var(--surface)", borderColor: "var(--rule)" }}
    >
      <div className="min-w-[16rem] flex-1">
        <label htmlFor="search" className="mb-1 block text-[12.5px] font-medium">
          Search
        </label>
        <TextInput
          id="search"
          value={filters.q}
          onChange={(q) => onChange({ ...filters, q })}
          placeholder="Host, path, workstation, rule or request id"
        />
      </div>
      <div>
        <label htmlFor="action" className="mb-1 block text-[12.5px] font-medium">
          Outcome
        </label>
        <Select
          id="action"
          value={filters.action}
          onChange={(action) => onChange({ ...filters, action })}
          options={[
            { value: "", label: "Any" },
            { value: "allow", label: "Forwarded" },
            { value: "monitor", label: "Flagged" },
            { value: "block", label: "Stopped" },
          ]}
        />
      </div>
      <div>
        <label htmlFor="service" className="mb-1 block text-[12.5px] font-medium">
          Service
        </label>
        <TextInput id="service" value={filters.service} onChange={(service) => onChange({ ...filters, service })} placeholder="Any" />
      </div>
      {!live && (
        <div>
          <label htmlFor="rule" className="mb-1 block text-[12.5px] font-medium">
            Rule
          </label>
          <TextInput id="rule" value={filters.rule} onChange={(rule) => onChange({ ...filters, rule })} placeholder="Any" />
        </div>
      )}
      {dirty && (
        <Button variant="quiet" onClick={() => onChange(EMPTY)}>
          Reset
        </Button>
      )}
    </div>
  );
}

/**
 * One request, hung off the wire. The spine runs continuously down the
 * column; the marker where a row meets it says what happened.
 */
function EventRow({
  event,
  fresh,
  expanded,
  onToggle,
}: {
  event: AuditEvent;
  fresh: boolean;
  expanded: boolean;
  onToggle: () => void;
}) {
  const hasDetail =
    (event.findings?.length ?? 0) > 0 || (event.prompt?.length ?? 0) > 0 || event.error || event.reason;
  return (
    <li className={`border-b last:border-b-0 ${fresh ? "arriving" : ""}`} style={{ borderColor: "var(--rule)" }}>
      <button
        onClick={onToggle}
        className="flex w-full items-stretch gap-3 px-4 py-1.5 text-left"
        aria-expanded={expanded}
        aria-label={`${actionLabel(event.action)} ${clockTime(event.ts)} ${event.host ?? ""}${event.path ?? ""}${
          event.rule ? `, rule ${event.rule}` : ""
        }`}
      >
        <time className="wire w-[68px] shrink-0 self-center" style={{ color: "var(--ink-faint)" }} dateTime={event.ts}>
          {clockTime(event.ts)}
        </time>

        {/* The wire: one continuous line down the column, with each request's
            outcome marked where it meets it. */}
        <span className="relative flex w-[26px] shrink-0 items-center justify-center" aria-hidden>
          <span className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2" style={{ background: "var(--wire)" }} />
          <span className="relative flex items-center">
            <DecisionMark action={event.action} />
          </span>
        </span>

        <span className="wire min-w-0 flex-1 truncate self-center">
          <span style={{ color: "var(--ink)" }}>{event.host}</span>
          <span style={{ color: "var(--ink-faint)" }}>{event.path}</span>
        </span>

        {event.service && (
          <span className="hidden w-[86px] shrink-0 truncate text-[12px] sm:block self-center" style={{ color: "var(--ink-muted)" }}>
            {event.service}
          </span>
        )}
        {event.rule ? (
          <span className="w-[92px] shrink-0 truncate text-[12px] font-medium self-center" style={{ color: actionColor(event.action) }}>
            {event.rule}
          </span>
        ) : (
          <span className="w-[92px] shrink-0 self-center" />
        )}
        <span className="w-[76px] shrink-0 text-[12px] self-center" style={{ color: actionColor(event.action) }}>
          {actionLabel(event.action)}
        </span>
        <span className="tnum hidden w-[56px] shrink-0 text-right text-[12px] md:block self-center" style={{ color: "var(--ink-faint)" }}>
          {event.latency_ms}ms
        </span>
      </button>

      {expanded && (
        <div className="px-4 pb-3 pl-[110px]">
          {hasDetail ? (
            <>
              {event.findings && event.findings.length > 0 && (
                <table className="w-full text-[12px]">
                  <thead>
                    <tr style={{ color: "var(--ink-faint)" }}>
                      <th className="py-1 pr-4 text-left font-medium">What was found</th>
                      <th className="py-1 pr-4 text-left font-medium">Severity</th>
                      <th className="py-1 pr-4 text-left font-medium">Where in the prompt</th>
                      <th className="py-1 text-left font-medium">Match</th>
                    </tr>
                  </thead>
                  <tbody>
                    {event.findings.map((f, i) => (
                      <tr key={i} className="border-t" style={{ borderColor: "var(--rule)" }}>
                        <td className="wire py-1 pr-4">{f.detector}</td>
                        <td className="py-1 pr-4">
                          <Severity level={f.severity} />
                        </td>
                        <td className="wire py-1 pr-4" style={{ color: "var(--ink-muted)" }}>
                          {f.segment}
                          {f.role ? ` (${f.role})` : ""}
                        </td>
                        <td className="wire py-1">{f.preview}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {event.prompt && event.prompt.length > 0 && (
                <div className="mt-2">
                  <p className="mb-1 text-[12px]" style={{ color: "var(--ink-faint)" }}>
                    What was sent
                  </p>
                  <ul className="border" style={{ borderColor: "var(--rule)" }}>
                    {event.prompt.map((seg, i) => (
                      <li key={i} className="border-b px-2 py-1.5 last:border-b-0" style={{ borderColor: "var(--rule)" }}>
                        <div className="flex items-baseline gap-2">
                          <span className="wire" style={{ color: "var(--ink-faint)" }}>
                            {seg.path}
                          </span>
                          {seg.role && (
                            <span className="text-[11px]" style={{ color: "var(--ink-muted)" }}>
                              {seg.role}
                            </span>
                          )}
                        </div>
                        <p className="mt-0.5 max-h-40 overflow-y-auto whitespace-pre-wrap text-[12.5px]">{seg.text}</p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <dl className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-[12px]" style={{ color: "var(--ink-muted)" }}>
                <Meta label="Request" value={event.request_id} mono />
                <Meta label="Workstation" value={event.client_ip} mono />
                {event.user && <Meta label="User" value={event.user} />}
                {event.model && <Meta label="Model" value={event.model} mono />}
                {event.reason && <Meta label="Reason" value={event.reason} />}
                {event.block_mode && event.action === "block" && <Meta label="Reply" value={event.block_mode} />}
                {event.upstream_status ? <Meta label="Upstream" value={String(event.upstream_status)} /> : null}
                <Meta label="Seen" value={relativeTime(event.ts)} />
              </dl>
              {event.error && (
                <p className="mt-2 text-[12px]" style={{ color: "var(--block)" }}>
                  {event.error}
                </p>
              )}
            </>
          ) : (
            <p className="text-[12px]" style={{ color: "var(--ink-muted)" }}>
              Nothing was found in this prompt. It was forwarded unchanged. To see the text itself, turn on
              audit.capture_prompts.
            </p>
          )}
        </div>
      )}
    </li>
  );
}

function Meta({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <div className="flex gap-1.5">
      <dt>{label}</dt>
      <dd className={mono ? "wire" : ""} style={{ color: "var(--ink)" }}>
        {value}
      </dd>
    </div>
  );
}
