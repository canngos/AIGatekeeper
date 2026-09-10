import { useState } from "react";
import type { ConfigDoc, ServiceConfig } from "../api/types";
import { Button, Empty, Field, Select, TextInput } from "../components/primitives";
import { Fact, Row, Section, TextArea, splitLines, update } from "./shared";

const BLOCK_MODE_LABEL: Record<string, string> = {
  reject: "Refuses the request",
  synthetic: "Replies with an explanation",
};

export function Services({
  draft,
  setDraft,
  extractors,
}: {
  draft: ConfigDoc;
  setDraft: (d: ConfigDoc) => void;
  extractors: string[];
}) {
  const [open, setOpen] = useState<number | null>(null);
  const services = draft.services ?? [];
  const ruleIds = (draft.rules ?? []).map((r) => r.id);

  return (
    <Section
      title="What gets inspected"
      description="Each destination listed here is decrypted and its prompts are read. Anything not listed is tunnelled through untouched, so this list is the whole of what the proxy can see."
      action={
        <Button
          onClick={() =>
            update(draft, setDraft, (d) => {
              d.services = [
                ...(d.services ?? []),
                { name: "new-service", hosts: [], extractor: "generic", block_mode: "reject", rules: [] },
              ];
              setOpen(d.services.length - 1);
            })
          }
        >
          Add destination
        </Button>
      }
    >
      {services.length === 0 && <Empty title="Nothing is inspected yet">Add a destination to start reading prompts sent to it.</Empty>}
      {services.map((svc, i) => (
        <Row
          key={i}
          open={open === i}
          onToggle={() => setOpen(open === i ? null : i)}
          title={svc.name || "Unnamed"}
          facts={
            <>
              <Fact mono>{summariseHosts(svc.hosts)}</Fact>
              <Fact>{BLOCK_MODE_LABEL[svc.block_mode] ?? svc.block_mode}</Fact>
              <Fact tone={(svc.rules ?? []).length === 0 ? "var(--monitor)" : undefined}>
                {(svc.rules ?? []).length === 0 ? "no rules applied" : (svc.rules ?? []).join(", ")}
              </Fact>
            </>
          }
        >
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Name" hint="Shown in traffic and alerts.">
              <TextInput value={svc.name} onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].name = v))} />
            </Field>
            <Field label="Reads request bodies as" hint="The API shape this destination speaks.">
              <Select
                value={svc.extractor}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].extractor = v))}
                options={extractors.map((e) => ({ value: e, label: e }))}
              />
            </Field>
            <Field label="Host names" hint="One regular expression per line, anchored with ^ and $ so a lookalike domain cannot match.">
              <TextArea
                value={(svc.hosts ?? []).join("\n")}
                mono
                rows={3}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].hosts = splitLines(v)))}
              />
            </Field>
            <Field label="Paths never inspected" hint="One regular expression per line. Health probes and telemetry, which carry no prompt.">
              <TextArea
                value={(svc.passthrough_paths ?? []).join("\n")}
                mono
                rows={3}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].passthrough_paths = splitLines(v)))}
              />
            </Field>
            <Field
              label="When a request is stopped"
              hint="A refusal is honest but shows in the IDE as a generic error. A stand-in reply appears in the chat and tells the developer which rule stopped them."
            >
              <Select
                value={svc.block_mode}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].block_mode = v as ServiceConfig["block_mode"]))}
                options={[
                  { value: "reject", label: "Refuse the request (403)" },
                  { value: "synthetic", label: "Reply with an explanation" },
                ]}
              />
            </Field>
            <Field label="Rules applied" hint="A prompt is checked against every rule ticked here.">
              <div className="flex flex-wrap gap-x-4 gap-y-1 pt-1">
                {ruleIds.length === 0 && (
                  <span className="text-[12.5px]" style={{ color: "var(--ink-faint)" }}>
                    Add a rule first.
                  </span>
                )}
                {ruleIds.map((id) => {
                  const on = (svc.rules ?? []).includes(id);
                  return (
                    <label key={id} className="flex items-center gap-1.5 text-[12.5px]">
                      <input
                        type="checkbox"
                        checked={on}
                        onChange={() =>
                          update(draft, setDraft, (d) => {
                            const list = new Set(d.services[i].rules ?? []);
                            if (on) list.delete(id);
                            else list.add(id);
                            d.services[i].rules = [...list];
                          })
                        }
                      />
                      {id}
                    </label>
                  );
                })}
              </div>
            </Field>
          </div>
          <div className="mt-3 border-t pt-3" style={{ borderColor: "var(--rule)" }}>
            <Button
              variant="danger"
              onClick={() => {
                setOpen(null);
                update(draft, setDraft, (d) => void (d.services as ServiceConfig[]).splice(i, 1));
              }}
            >
              Remove this destination
            </Button>
          </div>
        </Row>
      ))}
    </Section>
  );
}

function summariseHosts(hosts?: string[] | null): string {
  const list = hosts ?? [];
  if (list.length === 0) return "no host names";
  const first = list[0].replace(/^\^/, "").replace(/\$$/, "").replace(/\\/g, "");
  return list.length === 1 ? first : `${first} and ${list.length - 1} more`;
}
