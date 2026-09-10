import type { ReactNode } from "react";
import type { Action } from "../api/types";

/** A bordered region. No shadows, no nested radii: one hairline, one job. */
export function Panel({
  title,
  actions,
  children,
  flush,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
}) {
  return (
    <section
      className="border"
      style={{ background: "var(--surface)", borderColor: "var(--rule)" }}
    >
      {(title || actions) && (
        <header
          className="flex items-center justify-between gap-3 border-b px-4 py-2.5"
          style={{ borderColor: "var(--rule)" }}
        >
          <h2 className="text-[13px] font-semibold">{title}</h2>
          {actions}
        </header>
      )}
      <div className={flush ? "" : "p-4"}>{children}</div>
    </section>
  );
}

export function Button({
  children,
  onClick,
  type = "button",
  variant = "default",
  disabled,
  title,
}: {
  children: ReactNode;
  onClick?: () => void;
  type?: "button" | "submit";
  variant?: "default" | "primary" | "quiet" | "danger";
  disabled?: boolean;
  title?: string;
}) {
  const style: React.CSSProperties = { borderColor: "var(--rule-strong)" };
  if (variant === "primary") {
    style.background = "var(--accent)";
    style.color = "var(--accent-ink)";
    style.borderColor = "var(--accent)";
  } else if (variant === "danger") {
    style.color = "var(--block)";
    style.borderColor = "var(--block)";
  } else if (variant === "quiet") {
    style.borderColor = "transparent";
    style.color = "var(--ink-muted)";
  } else {
    style.background = "var(--surface)";
  }
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="inline-flex items-center gap-1.5 border px-2.5 py-1 text-[13px] font-medium transition-colors disabled:opacity-45"
      style={style}
    >
      {children}
    </button>
  );
}

/**
 * The decision marker, drawn as a bead on the wire. Shape carries the
 * meaning as much as colour does: an open ring passed through the gate, a
 * filled square was stopped, a half-filled ring was recorded but forwarded.
 * Each is filled with the surface colour so the wire does not show through.
 */
export function DecisionMark({ action }: { action?: Action | string }) {
  const size = 9;
  if (action === "block") {
    return (
      <span
        aria-hidden
        style={{ width: size, height: size, background: "var(--block)", display: "inline-block" }}
      />
    );
  }
  if (action === "monitor") {
    return (
      <span
        aria-hidden
        style={{
          width: size,
          height: size,
          borderRadius: "50%",
          border: `2px solid var(--monitor)`,
          background: `linear-gradient(to right, var(--monitor) 50%, var(--surface) 50%)`,
          display: "inline-block",
        }}
      />
    );
  }
  return (
    <span
      aria-hidden
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        border: `2px solid var(--allow)`,
        background: "var(--surface)",
        display: "inline-block",
      }}
    />
  );
}

export function actionColor(action?: string): string {
  switch (action) {
    case "block":
      return "var(--block)";
    case "monitor":
      return "var(--monitor)";
    case "allow":
      return "var(--allow)";
    default:
      return "var(--ink-faint)";
  }
}

export function actionSoft(action?: string): string {
  switch (action) {
    case "block":
      return "var(--block-soft)";
    case "monitor":
      return "var(--monitor-soft)";
    case "allow":
      return "var(--allow-soft)";
    default:
      return "var(--surface-sunken)";
  }
}

/** Human-readable verbs for what the proxy did. */
export function actionLabel(action?: string): string {
  switch (action) {
    case "block":
      return "Stopped";
    case "monitor":
      return "Flagged";
    case "allow":
      return "Forwarded";
    default:
      return action ?? "";
  }
}

export function Tag({ children, tone }: { children: ReactNode; tone?: string }) {
  return (
    <span
      className="inline-block px-1.5 py-0.5 text-[11px] font-medium"
      style={{ background: actionSoft(tone), color: actionColor(tone) }}
    >
      {children}
    </span>
  );
}

export function Severity({ level }: { level: string }) {
  const tone = level === "critical" || level === "high" ? "block" : level === "medium" ? "monitor" : undefined;
  return <Tag tone={tone}>{level}</Tag>;
}

/**
 * A labelled control. The hint sits outside the <label> so it does not
 * become part of the control's accessible name.
 */
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div>
      <label className="block">
        <span className="mb-1 block text-[12.5px] font-medium">{label}</span>
        {children}
      </label>
      {hint && (
        <p className="mt-1 text-[12px]" style={{ color: "var(--ink-faint)" }}>
          {hint}
        </p>
      )}
    </div>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
  mono,
  autoFocus,
  name,
  id,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
  autoFocus?: boolean;
  name?: string;
  id?: string;
}) {
  return (
    <input
      id={id}
      name={name}
      type={type}
      value={value}
      autoFocus={autoFocus}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className={`w-full border px-2 py-1 text-[13px] ${mono ? "wire" : ""}`}
      style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
    />
  );
}

export function Select({
  value,
  onChange,
  options,
  id,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  id?: string;
}) {
  return (
    <select
      id={id}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="border px-2 py-1 text-[13px]"
      style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="px-4 py-10 text-center">
      <p className="text-[13px] font-medium">{title}</p>
      {children && (
        <p className="mx-auto mt-1 max-w-[46ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
          {children}
        </p>
      )}
    </div>
  );
}

export function Notice({ tone = "info", children }: { tone?: "info" | "error" | "ok"; children: ReactNode }) {
  const color = tone === "error" ? "var(--block)" : tone === "ok" ? "var(--allow)" : "var(--accent)";
  const bg = tone === "error" ? "var(--block-soft)" : tone === "ok" ? "var(--allow-soft)" : "var(--accent-soft)";
  return (
    <div
      role={tone === "error" ? "alert" : undefined}
      className="border-l-2 px-3 py-2 text-[12.5px]"
      style={{ borderColor: color, background: bg }}
    >
      {children}
    </div>
  );
}

export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const secs = Math.round((Date.now() - then) / 1000);
  if (secs < 45) return `${Math.max(secs, 0)}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function clockTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString(undefined, { hour12: false });
}
