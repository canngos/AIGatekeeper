import { useState } from "react";
import type { AccessKeyPrefix, ConfigDoc, DetectorInfo, DetectorOption } from "../api/types";
import { Button, Severity, Tag } from "../components/primitives";
import { update } from "./shared";

/** Groups in the order a security lead thinks about them; anything the
    server adds later falls in after these, alphabetically. */
const GROUP_ORDER = ["Keys and tokens", "Personal data"];

function groupsOf(detectors: DetectorInfo[]): string[] {
  const seen = [...new Set(detectors.map((d) => d.group || "Other"))];
  return seen.sort((a, b) => {
    const ia = GROUP_ORDER.indexOf(a);
    const ib = GROUP_ORDER.indexOf(b);
    if (ia === -1 && ib === -1) return a.localeCompare(b);
    if (ia === -1) return 1;
    if (ib === -1) return -1;
    return ia - ib;
  });
}

/**
 * The list of things a rule looks for.
 *
 * Detectors are offered by name and grouped, because choosing what to watch
 * for is a security decision and should not require reading identifiers. A
 * detector that can be tuned opens its settings in place, so the prefixes a
 * key is recognised by sit next to the checkbox that turns them on.
 */
export function DetectorPicker({
  draft,
  setDraft,
  index,
  detectors,
}: {
  draft: ConfigDoc;
  setDraft: (d: ConfigDoc) => void;
  index: number;
  detectors: DetectorInfo[];
}) {
  const rule = draft.rules[index];
  const selected = new Set(rule.detectors ?? []);
  // A retired detector is hidden unless this rule still uses it, in which
  // case hiding it would leave something enabled that nobody can see.
  const visible = detectors.filter((d) => !d.deprecated || selected.has(d.id));

  function toggle(id: string) {
    update(draft, setDraft, (d) => {
      const list = new Set(d.rules[index].detectors ?? []);
      if (list.has(id)) list.delete(id);
      else list.add(id);
      d.rules[index].detectors = [...list];
    });
  }

  function replace(oldID: string, newID: string) {
    update(draft, setDraft, (d) => {
      const list = new Set(d.rules[index].detectors ?? []);
      list.delete(oldID);
      list.add(newID);
      d.rules[index].detectors = [...list];
    });
  }

  return (
    <div className="grid gap-3">
      <div className="flex items-baseline justify-between">
        <span className="text-[12.5px] font-medium">Looks for</span>
        <span className="text-[12px]" style={{ color: "var(--ink-faint)" }}>
          {selected.size} of {visible.length} selected
        </span>
      </div>

      {groupsOf(visible).map((group) => (
        <div key={group}>
          <h4 className="mb-1 text-[12px] font-semibold" style={{ color: "var(--ink-muted)" }}>
            {group}
          </h4>
          <ul className="border" style={{ borderColor: "var(--rule)" }}>
            {visible
              .filter((d) => (d.group || "Other") === group)
              .sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id))
              .map((d) => (
                <DetectorRow
                  key={d.id}
                  detector={d}
                  checked={selected.has(d.id)}
                  onToggle={() => toggle(d.id)}
                  onReplace={d.replaced_by ? () => replace(d.id, d.replaced_by!) : undefined}
                  draft={draft}
                  setDraft={setDraft}
                  index={index}
                />
              ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function DetectorRow({
  detector,
  checked,
  onToggle,
  onReplace,
  draft,
  setDraft,
  index,
}: {
  detector: DetectorInfo;
  checked: boolean;
  onToggle: () => void;
  onReplace?: () => void;
  draft: ConfigDoc;
  setDraft: (d: ConfigDoc) => void;
  index: number;
}) {
  const [showSettings, setShowSettings] = useState(false);
  const tunable = (detector.options?.length ?? 0) > 0;

  return (
    <li className="border-b px-3 py-2 last:border-b-0" style={{ borderColor: "var(--rule)" }}>
      <div className="flex items-start gap-2.5">
        <input
          type="checkbox"
          id={`det-${index}-${detector.id}`}
          className="mt-[3px]"
          checked={checked}
          onChange={onToggle}
        />
        <div className="min-w-0 flex-1">
          <label htmlFor={`det-${index}-${detector.id}`} className="text-[13px] font-medium">
            {detector.name || detector.id}
          </label>
          <p className="text-[12px]" style={{ color: "var(--ink-faint)" }}>
            {detector.description}
          </p>
          {detector.deprecated && onReplace && (
            <p className="mt-1 text-[12px]">
              <Tag tone="monitor">Retired</Tag>{" "}
              <button type="button" onClick={onReplace} className="underline underline-offset-2">
                Switch to {detector.replaced_by}
              </button>{" "}
              <span style={{ color: "var(--ink-faint)" }}>to cover more than one cloud.</span>
            </p>
          )}
        </div>
        <span className="w-16 shrink-0 text-right">
          <Severity level={detector.severity} />
        </span>
        <span className="w-[104px] shrink-0 text-right">
          {tunable && checked && (
            <Button variant="quiet" onClick={() => setShowSettings((v) => !v)}>
              {showSettings ? "Hide settings" : "Settings"}
            </Button>
          )}
        </span>
      </div>
      {tunable && checked && showSettings && (
        <div
          className="mt-2 ml-6 border-l-2 pl-3"
          style={{ borderColor: "var(--accent)" }}
        >
          {detector.options!.map((opt) => (
            <OptionEditor key={opt.name} detector={detector.id} option={opt} draft={draft} setDraft={setDraft} index={index} />
          ))}
        </div>
      )}
    </li>
  );
}

function readOption(draft: ConfigDoc, index: number, detector: string, option: DetectorOption): unknown {
  const stored = draft.rules[index].options?.[detector]?.[option.name];
  return stored === undefined ? option.default : stored;
}

function writeOption(
  draft: ConfigDoc,
  setDraft: (d: ConfigDoc) => void,
  index: number,
  detector: string,
  name: string,
  value: unknown,
) {
  update(draft, setDraft, (d) => {
    const rule = d.rules[index];
    rule.options = { ...(rule.options ?? {}) };
    rule.options[detector] = { ...(rule.options[detector] ?? {}), [name]: value };
  });
}

function OptionEditor({
  detector,
  option,
  draft,
  setDraft,
  index,
}: {
  detector: string;
  option: DetectorOption;
  draft: ConfigDoc;
  setDraft: (d: ConfigDoc) => void;
  index: number;
}) {
  const value = readOption(draft, index, detector, option);
  const label = option.label || option.name;
  const set = (v: unknown) => writeOption(draft, setDraft, index, detector, option.name, v);

  if (option.type === "prefix_list") {
    return (
      <PrefixTable
        label={label}
        description={option.description}
        value={(value as AccessKeyPrefix[]) ?? []}
        customised={draft.rules[index].options?.[detector]?.[option.name] !== undefined}
        defaults={option.default as AccessKeyPrefix[]}
        onChange={set}
        onReset={() =>
          update(draft, setDraft, (d) => {
            const opts = d.rules[index].options?.[detector];
            if (opts) delete opts[option.name];
          })
        }
      />
    );
  }

  if (option.type === "bool") {
    return (
      <div className="py-1.5">
        <label className="flex items-center gap-2 text-[12.5px]">
          <input type="checkbox" checked={Boolean(value)} onChange={(e) => set(e.target.checked)} />
          {label}
        </label>
        <p className="ml-6 text-[12px]" style={{ color: "var(--ink-faint)" }}>
          {option.description}
        </p>
      </div>
    );
  }

  return (
    <div className="py-1.5">
      <label className="flex items-center gap-2 text-[12.5px]">
        <span className="w-40">{label}</span>
        <input
          type={option.type === "number" ? "number" : "text"}
          value={String(value ?? "")}
          onChange={(e) => set(option.type === "number" ? Number(e.target.value) : e.target.value)}
          className="w-28 border px-2 py-1 text-[13px]"
          style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
        />
      </label>
      <p className="mt-0.5 text-[12px]" style={{ color: "var(--ink-faint)" }}>
        {option.description}
      </p>
    </div>
  );
}

/**
 * The prefixes an access key is recognised by.
 *
 * Until it is edited the table shows the shipped defaults, marked as such,
 * because an empty table would suggest nothing is being looked for. The
 * first edit copies the whole list into the policy: from then on it is the
 * deployment's list, and Reset puts the shipped one back.
 */
function PrefixTable({
  label,
  description,
  value,
  defaults,
  customised,
  onChange,
  onReset,
}: {
  label: string;
  description: string;
  value: AccessKeyPrefix[];
  defaults: AccessKeyPrefix[];
  customised: boolean;
  onChange: (v: AccessKeyPrefix[]) => void;
  onReset: () => void;
}) {
  const rows = value.length > 0 ? value : defaults;

  const edit = (i: number, patch: Partial<AccessKeyPrefix>) => {
    const next = rows.map((r, j) => (j === i ? { ...r, ...patch } : { ...r }));
    onChange(next);
  };

  return (
    <div className="py-1.5">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[12.5px] font-medium">{label}</span>
        {customised ? (
          <Button variant="quiet" onClick={onReset}>
            Reset to defaults
          </Button>
        ) : (
          <span className="text-[12px]" style={{ color: "var(--ink-faint)" }}>
            Defaults. Editing makes a copy you own.
          </span>
        )}
      </div>
      <p className="mb-1.5 max-w-[70ch] text-[12px]" style={{ color: "var(--ink-faint)" }}>
        {description}
      </p>
      <table className="w-full border-collapse text-[12.5px]">
        <thead>
          <tr style={{ color: "var(--ink-faint)" }}>
            <th className="border-b py-1 pr-2 text-left font-medium" style={{ borderColor: "var(--rule)" }}>
              Prefix
            </th>
            <th className="border-b py-1 pr-2 text-left font-medium" style={{ borderColor: "var(--rule)" }}>
              Key length
            </th>
            <th className="border-b py-1 pr-2 text-left font-medium" style={{ borderColor: "var(--rule)" }}>
              Vendor
            </th>
            <th className="border-b py-1" style={{ borderColor: "var(--rule)" }} />
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              <td className="py-1 pr-2">
                <input
                  aria-label={`Prefix ${i + 1}`}
                  value={row.prefix ?? ""}
                  onChange={(e) => edit(i, { prefix: e.target.value })}
                  className="wire w-28 border px-1.5 py-0.5"
                  style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                />
              </td>
              <td className="py-1 pr-2">
                <input
                  aria-label={`Key length ${i + 1}`}
                  type="number"
                  placeholder="any"
                  value={row.length ?? ""}
                  onChange={(e) => edit(i, { length: e.target.value === "" ? undefined : Number(e.target.value) })}
                  className="w-20 border px-1.5 py-0.5"
                  style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                />
              </td>
              <td className="py-1 pr-2">
                <input
                  aria-label={`Vendor ${i + 1}`}
                  value={row.note ?? ""}
                  onChange={(e) => edit(i, { note: e.target.value })}
                  className="w-full border px-1.5 py-0.5"
                  style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                />
              </td>
              <td className="py-1 text-right">
                <Button
                  variant="quiet"
                  title="Remove this prefix"
                  onClick={() => onChange(rows.filter((_, j) => j !== i))}
                >
                  Remove
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-1.5">
        <Button onClick={() => onChange([...rows, { prefix: "" }])}>Add prefix</Button>
      </div>
      <p className="mt-1.5 max-w-[70ch] text-[12px]" style={{ color: "var(--ink-faint)" }}>
        Leave the length blank when a vendor's keys vary in length. A fixed length is stricter and is what keeps a
        word like ASIAPACIFICREGION from reading as a key.
      </p>
    </div>
  );
}
