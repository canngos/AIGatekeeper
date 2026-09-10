import { useState } from "react";
import type { AccessKeyPrefix, ConfigDoc, CustomPattern, DetectorInfo, DetectorOption } from "../api/types";
import { Button, Severity, Tag } from "../components/primitives";
import { update } from "./shared";

/** Groups in the order a security lead thinks about them; anything the
    server adds later falls in after these, alphabetically. */
const GROUP_ORDER = ["Keys and tokens", "Personal data"];

/** Where a pattern with no group of its own is filed. */
const OWN_GROUP = "Your own";

function sortGroups(names: Iterable<string>): string[] {
  return [...new Set(names)].sort((a, b) => {
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
  const custom = rule.regex ?? [];
  const groups = sortGroups([
    ...visible.map((d) => d.group || OWN_GROUP),
    ...custom.map((c) => c.group || OWN_GROUP),
    OWN_GROUP,
  ]);

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
          {selected.size} built in, {custom.length} of your own
        </span>
      </div>

      {groups.map((group) => {
        const builtins = visible
          .filter((d) => (d.group || OWN_GROUP) === group)
          .sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id));
        const mine = custom
          .map((pattern, at) => ({ pattern, at }))
          .filter(({ pattern }) => (pattern.group || OWN_GROUP) === group);
        return (
          <div key={group}>
            <h4 className="mb-1 text-[12px] font-semibold" style={{ color: "var(--ink-muted)" }}>
              {group}
            </h4>
            <div className="border" style={{ borderColor: "var(--rule)" }}>
              {builtins.length > 0 && (
                <ul>
                  {builtins.map((d) => (
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
              )}
              <CustomPatterns
                group={group}
                entries={mine}
                all={custom}
                ruleSeverity={rule.severity}
                onChange={(next) => update(draft, setDraft, (d) => void (d.rules[index].regex = next))}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/**
 * The patterns a deployment writes itself, shown in the group it filed them
 * under, so an internal key format sits with the other key formats instead
 * of in a box at the bottom of the page.
 *
 * The name is not decoration. It is what every finding, alert and report
 * will call this thing, so it comes first and it is required.
 */
function CustomPatterns({
  group,
  entries,
  all,
  ruleSeverity,
  onChange,
}: {
  group: string;
  entries: { pattern: CustomPattern; at: number }[];
  all: CustomPattern[];
  ruleSeverity: string;
  onChange: (next: CustomPattern[]) => void;
}) {
  const edit = (at: number, patch: Partial<CustomPattern>) =>
    onChange(all.map((p, i) => (i === at ? { ...p, ...patch } : p)));
  const label = (row: number, field: string) => `${group} pattern ${row + 1} ${field}`;

  return (
    <div className="border-t px-3 py-2" style={{ borderColor: "var(--rule)", background: "var(--surface-sunken)" }}>
      {entries.length > 0 && (
        <table className="w-full border-collapse text-[12.5px]">
          <thead>
            <tr style={{ color: "var(--ink-faint)" }}>
              {["Name", "Pattern", "Severity", "Shortest match"].map((h) => (
                <th key={h} className="border-b py-1 pr-2 text-left font-medium" style={{ borderColor: "var(--rule)" }}>
                  {h}
                </th>
              ))}
              <th className="border-b py-1" style={{ borderColor: "var(--rule)" }} />
            </tr>
          </thead>
          <tbody>
            {entries.map(({ pattern, at }, row) => (
              <tr key={at}>
                <td className="w-44 py-1 pr-2">
                  <input
                    aria-label={label(row, "name")}
                    value={pattern.id ?? ""}
                    placeholder="corp_gateway_key"
                    onChange={(e) => edit(at, { id: e.target.value })}
                    className="wire w-full border px-1.5 py-0.5"
                    style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                  />
                </td>
                <td className="py-1 pr-2">
                  <input
                    aria-label={label(row, "expression")}
                    value={pattern.pattern ?? ""}
                    placeholder="\bCORPKEY-[A-Z0-9]{24}\b"
                    onChange={(e) => edit(at, { pattern: e.target.value })}
                    className="wire w-full border px-1.5 py-0.5"
                    style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                  />
                </td>
                <td className="py-1 pr-2">
                  <select
                    aria-label={label(row, "severity")}
                    value={pattern.severity ?? ""}
                    onChange={(e) => edit(at, { severity: (e.target.value || undefined) as CustomPattern["severity"] })}
                    className="border px-1 py-0.5 text-[12.5px]"
                    style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                  >
                    <option value="">Same as the rule ({ruleSeverity})</option>
                    {["low", "medium", "high", "critical"].map((sev) => (
                      <option key={sev} value={sev}>
                        {sev}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="py-1 pr-2">
                  <input
                    aria-label={label(row, "shortest match")}
                    type="number"
                    placeholder="any"
                    value={pattern.min_length ?? ""}
                    onChange={(e) => edit(at, { min_length: e.target.value === "" ? undefined : Number(e.target.value) })}
                    className="w-20 border px-1.5 py-0.5"
                    style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                  />
                </td>
                <td className="py-1 text-right">
                  <Button variant="quiet" onClick={() => onChange(all.filter((_, i) => i !== at))}>
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="mt-1 flex flex-wrap items-baseline gap-3">
        <Button onClick={() => onChange([...all, { id: "", pattern: "", group }])}>Add your own</Button>
        <span className="max-w-[62ch] text-[12px]" style={{ color: "var(--ink-faint)" }}>
          {entries.length === 0
            ? "A format only your company would recognise, matched here alongside the built-in ones."
            : "The name is what every finding and alert will call it. Patterns are RE2: no lookahead, no backreferences."}
        </span>
      </div>
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
