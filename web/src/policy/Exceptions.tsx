import type { ConfigDoc } from "../api/types";
import { Field, TextInput } from "../components/primitives";
import { Section, TextArea, splitLines, update } from "./shared";

/**
 * Exceptions are the quietest part of the policy and the one that goes
 * wrong most expensively: anything listed here is never reported again. So
 * they are shown as one short screen rather than hidden behind a tab, with
 * the two kinds kept apart. Silencing a value is small. Letting a whole
 * machine skip inspection is not.
 */
export function Exceptions({ draft, setDraft }: { draft: ConfigDoc; setDraft: (d: ConfigDoc) => void }) {
  const al = draft.allowlist ?? {};
  const set = (key: string, value: unknown) =>
    update(draft, setDraft, (d) => {
      d.allowlist = { ...(d.allowlist ?? {}), [key]: value };
    });

  return (
    <Section
      title="What to ignore"
      description="Use these to cut false alarms instead of turning a rule off. The documentation key AKIAIOSFODNN7EXAMPLE is listed by default, which is why pasting it never triggers anything."
    >
      <div className="grid gap-3 p-3 md:grid-cols-2">
        <Field label="Values never flagged" hint="One per line. Sample keys from documentation, test card numbers.">
          <TextArea rows={4} mono value={(al.values ?? []).join("\n")} onChange={(v) => set("values", splitLines(v))} />
        </Field>
        <Field label="Patterns never flagged" hint="One regular expression per line.">
          <TextArea rows={4} mono value={(al.patterns ?? []).join("\n")} onChange={(v) => set("patterns", splitLines(v))} />
        </Field>
        <Field label="Your own email domains" hint="One per line, so internal addresses are not read as a leak.">
          <TextArea rows={3} mono value={(al.email_domains ?? []).join("\n")} onChange={(v) => set("email_domains", splitLines(v))} />
        </Field>
        <Field
          label="Parts of a prompt never scanned"
          hint="One JSON path per line, such as the tool definitions an agent resends on every turn."
        >
          <TextArea rows={3} mono value={(al.segment_paths ?? []).join("\n")} onChange={(v) => set("segment_paths", splitLines(v))} />
        </Field>
      </div>
      <div className="border-t p-3" style={{ borderColor: "var(--rule)" }}>
        <p className="mb-2 max-w-[78ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
          These skip inspection entirely: prompts from them are forwarded without being read. Keep the list short.
        </p>
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Networks that skip inspection" hint="One CIDR block per line, for build agents and other trusted automation.">
            <TextArea rows={3} mono value={(al.client_cidrs ?? []).join("\n")} onChange={(v) => set("client_cidrs", splitLines(v))} />
          </Field>
          <Field
            label="Shared secret header"
            hint={`A caller sending ${al.header_bypass?.name || "X-AIGK-Bypass"} with this value skips inspection. Leave it empty to disable.`}
          >
            <TextInput
              mono
              value={al.header_bypass?.token ?? ""}
              onChange={(v) => set("header_bypass", { name: al.header_bypass?.name || "X-AIGK-Bypass", token: v })}
            />
          </Field>
        </div>
      </div>
    </Section>
  );
}
