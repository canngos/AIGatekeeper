import type { ReactNode } from "react";
import type { ConfigDoc } from "../api/types";

/** Applies a mutation to a copy of the draft, so React sees a new object. */
export function update(draft: ConfigDoc, setDraft: (d: ConfigDoc) => void, mutate: (d: ConfigDoc) => void) {
  const next = structuredClone(draft);
  mutate(next);
  setDraft(next);
}

export function splitLines(v: string): string[] {
  return v
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function TextArea({
  value,
  onChange,
  rows = 3,
  mono,
}: {
  value: string;
  onChange: (v: string) => void;
  rows?: number;
  mono?: boolean;
}) {
  return (
    <textarea
      value={value}
      rows={rows}
      onChange={(e) => onChange(e.target.value)}
      className={`w-full border px-2 py-1 text-[13px] ${mono ? "wire" : ""}`}
      style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
    />
  );
}

/**
 * One item in a list of services or rules, collapsed to a single line until
 * it is opened.
 *
 * The whole point of the page is that a policy is a short list of decisions.
 * Rendering every field of every item at once buries that list, so an item
 * shows only its name and what it does, and opens to be edited. One open at
 * a time keeps the list on screen while you work.
 */
export function Row({
  open,
  onToggle,
  title,
  facts,
  children,
}: {
  open: boolean;
  onToggle: () => void;
  title: ReactNode;
  facts: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="border-b last:border-b-0" style={{ borderColor: "var(--rule)" }}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-3 py-2 text-left"
        style={{ background: open ? "var(--surface-sunken)" : "transparent" }}
      >
        <span aria-hidden className="text-[10px]" style={{ color: "var(--ink-faint)" }}>
          {open ? "▼" : "▶"}
        </span>
        <span className="w-40 shrink-0 truncate text-[13px] font-semibold">{title}</span>
        <span className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1 text-[12px]">{facts}</span>
      </button>
      {open && <div className="border-t px-3 py-3" style={{ borderColor: "var(--rule)" }}>{children}</div>}
    </div>
  );
}

/** A summary fact on a collapsed row: quiet by default, wire-mono for
    anything copied verbatim from the configuration. */
export function Fact({ children, mono, tone }: { children: ReactNode; mono?: boolean; tone?: string }) {
  return (
    <span className={mono ? "wire truncate" : "truncate"} style={{ color: tone ?? "var(--ink-muted)" }}>
      {children}
    </span>
  );
}

/** A titled group of rows with an action in its header. */
export function Section({
  title,
  description,
  action,
  children,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    // Named so each section is a landmark: with three lists of rows on one
    // page, "the rule called secrets" has to be distinguishable from "the
    // destination that applies the rule called secrets".
    <section className="grid gap-2" aria-label={title}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-[15px] font-semibold tracking-tight">{title}</h2>
        {action}
      </div>
      {description && (
        <p className="max-w-[78ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
          {description}
        </p>
      )}
      <div className="border" style={{ background: "var(--surface)", borderColor: "var(--rule)" }}>
        {children}
      </div>
    </section>
  );
}
