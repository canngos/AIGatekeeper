import { useState } from "react";
import type { ConfigDoc, DetectorInfo, RuleConfig } from "../api/types";
import { Button, Empty, Field, Severity, Select, TextInput } from "../components/primitives";
import { DetectorPicker } from "./Detectors";
import { Fact, Row, Section, TextArea, splitLines, update } from "./shared";

const ACTION_LABEL: Record<string, string> = {
  block: "Stops the request",
  monitor: "Records it and lets it through",
  allow: "Ignores it",
};

export function Rules({
  draft,
  setDraft,
  detectors,
}: {
  draft: ConfigDoc;
  setDraft: (d: ConfigDoc) => void;
  detectors: DetectorInfo[];
}) {
  const [open, setOpen] = useState<number | null>(null);
  const rules = draft.rules ?? [];
  const defaultAction = String(draft.default_action ?? "block");

  return (
    <Section
      title="What to look for"
      description="A rule pairs what to look for with what to do about it. Start a new rule on Records it, watch Traffic for a few days, then switch it to Stops the request."
      action={
        <Button
          onClick={() =>
            update(draft, setDraft, (d) => {
              d.rules = [...(d.rules ?? []), { id: "new-rule", severity: "medium", action: "monitor", detectors: [] }];
              setOpen(d.rules.length - 1);
            })
          }
        >
          Add rule
        </Button>
      }
    >
      {rules.length === 0 && <Empty title="No rules yet">Nothing is being looked for, so every prompt is forwarded.</Empty>}
      {rules.map((rule, i) => (
        <Row
          key={i}
          open={open === i}
          onToggle={() => setOpen(open === i ? null : i)}
          title={rule.id || "Unnamed"}
          facts={
            <>
              <Severity level={rule.severity} />
              <Fact>{ACTION_LABEL[rule.action ?? defaultAction] ?? rule.action}</Fact>
              <Fact>{summariseWhatItLooksFor(rule)}</Fact>
            </>
          }
        >
          <div className="grid gap-4">
            <div className="grid gap-3 md:grid-cols-3">
              <Field label="Name" hint="Recorded on every event this rule matches.">
                <TextInput value={rule.id} onChange={(v) => update(draft, setDraft, (d) => void (d.rules[i].id = v))} />
              </Field>
              <Field label="Severity" hint="Ranks this rule against others and drives alerting.">
                <Select
                  value={rule.severity}
                  onChange={(v) => update(draft, setDraft, (d) => void (d.rules[i].severity = v as RuleConfig["severity"]))}
                  options={["low", "medium", "high", "critical"].map((s) => ({ value: s, label: s }))}
                />
              </Field>
              <Field label="When it matches" hint={`Leave it on the default to follow default_action, currently ${defaultAction}.`}>
                <Select
                  value={rule.action ?? ""}
                  onChange={(v) => update(draft, setDraft, (d) => void (d.rules[i].action = (v || undefined) as RuleConfig["action"]))}
                  options={[
                    { value: "", label: `Use the default (${defaultAction})` },
                    { value: "block", label: "Stop the request" },
                    { value: "monitor", label: "Record it and let it through" },
                    { value: "allow", label: "Ignore it" },
                  ]}
                />
              </Field>
            </div>

            <DetectorPicker draft={draft} setDraft={setDraft} index={i} detectors={detectors} />

            <Field
              label="Your own words and phrases"
              hint="One per line. Project code names, customer names, anything that should not leave. For a format rather than a word, add a pattern in the list above."
            >
              <TextArea
                rows={4}
                value={(rule.keywords?.list ?? []).join("\n")}
                onChange={(v) =>
                  update(draft, setDraft, (d) => {
                    d.rules[i].keywords = { ...(d.rules[i].keywords ?? {}), list: splitLines(v) };
                  })
                }
              />
            </Field>
            {rule.keywords?.file && (
              <p className="text-[12px]" style={{ color: "var(--ink-faint)" }}>
                This rule also reads words from <span className="wire">{rule.keywords.file}</span>, which the forms do
                not edit.
              </p>
            )}

            <div className="border-t pt-3" style={{ borderColor: "var(--rule)" }}>
              <Button
                variant="danger"
                onClick={() => {
                  setOpen(null);
                  update(draft, setDraft, (d) => void (d.rules as RuleConfig[]).splice(i, 1));
                }}
              >
                Remove this rule
              </Button>
            </div>
          </div>
        </Row>
      ))}
    </Section>
  );
}

function summariseWhatItLooksFor(rule: RuleConfig): string {
  const parts: string[] = [];
  const n = (rule.detectors ?? []).length;
  if (n > 0) parts.push(`${n} built-in ${n === 1 ? "detector" : "detectors"}`);
  const words = (rule.keywords?.list ?? []).length;
  if (words > 0) parts.push(`${words} ${words === 1 ? "word" : "words"}`);
  if (rule.keywords?.file) parts.push("a word list");
  const patterns = (rule.regex ?? []).length;
  if (patterns > 0) parts.push(`${patterns} ${patterns === 1 ? "pattern" : "patterns"}`);
  return parts.length === 0 ? "looks for nothing yet" : parts.join(", ");
}
