import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { yaml as yamlLang } from "@codemirror/lang-yaml";
import { api } from "../api/client";
import type { ConfigDoc, DetectorInfo, Problem, RuleConfig, ServiceConfig } from "../api/types";
import { Page } from "../components/Layout";
import { Button, Empty, Field, Notice, Panel, Select, Severity, TextInput } from "../components/primitives";

type Tab = "services" | "rules" | "allowlist" | "yaml";

const TABS: { id: Tab; label: string }[] = [
  { id: "services", label: "Services" },
  { id: "rules", label: "Rules" },
  { id: "allowlist", label: "Exceptions" },
  { id: "yaml", label: "Raw file" },
];

export function Policy() {
  const qc = useQueryClient();
  const config = useQuery({ queryKey: ["config"], queryFn: api.config });
  const detectors = useQuery({ queryKey: ["detectors"], queryFn: api.detectors });

  const [tab, setTab] = useState<Tab>("services");
  const [draft, setDraft] = useState<ConfigDoc | null>(null);
  const [yamlDraft, setYamlDraft] = useState<string>("");
  const [problems, setProblems] = useState<Problem[]>([]);
  const [status, setStatus] = useState<{ tone: "ok" | "error" | "info"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [editingYaml, setEditingYaml] = useState(false);

  useEffect(() => {
    if (config.data) {
      setDraft(structuredClone(config.data.config));
      setYamlDraft(config.data.yaml);
      setEditingYaml(false);
    }
  }, [config.data]);

  const dirty = useMemo(() => {
    if (!config.data || !draft) return false;
    return editingYaml
      ? yamlDraft !== config.data.yaml
      : JSON.stringify(draft) !== JSON.stringify(config.data.config);
  }, [config.data, draft, yamlDraft, editingYaml]);

  function payload() {
    return editingYaml ? { yaml: yamlDraft } : { config: draft };
  }

  async function validate() {
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.validateConfig(payload());
      setProblems(res.errors ?? []);
      setStatus(
        res.ok
          ? { tone: "ok", text: "This configuration is valid." }
          : { tone: "error", text: "This configuration has problems that must be fixed before it can be applied." },
      );
    } catch (err) {
      setStatus({ tone: "error", text: err instanceof Error ? err.message : "Validation failed" });
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    if (!config.data) return;
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.applyConfig({ ...payload(), base_version: config.data.version });
      setProblems([]);
      setStatus({ tone: "ok", text: `Applied. The proxy is enforcing version ${res.version.slice(0, 12)}.` });
      await qc.invalidateQueries({ queryKey: ["config"] });
      await qc.invalidateQueries({ queryKey: ["status"] });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Apply failed";
      const body = (err as { body?: { errors?: Problem[] } }).body;
      setProblems(body?.errors ?? []);
      setStatus({
        tone: "error",
        text: message.includes("changed since")
          ? "Someone else changed the configuration while you were editing. Reload to see their version, then reapply your changes."
          : message,
      });
    } finally {
      setBusy(false);
    }
  }

  if (config.isLoading || !draft) {
    return (
      <Page title="Policy">
        <div className="h-64 animate-pulse border" style={{ background: "var(--surface-sunken)", borderColor: "var(--rule)" }} />
      </Page>
    );
  }
  if (config.error) {
    return (
      <Page title="Policy">
        <Notice tone="error">{String(config.error.message)}</Notice>
      </Page>
    );
  }

  return (
    <Page
      title="Policy"
      description={`Edited here and written straight to ${config.data?.path}. The proxy picks up changes without restarting.`}
      actions={
        <>
          <Button onClick={() => void validate()} disabled={busy}>
            Check
          </Button>
          <Button variant="primary" onClick={() => void apply()} disabled={busy || !dirty}>
            {busy ? "Applying" : "Apply changes"}
          </Button>
        </>
      }
    >
      <div className="grid gap-4">
        {status && <Notice tone={status.tone}>{status.text}</Notice>}
        {problems.length > 0 && (
          <Panel title="Problems to fix" flush>
            <ul>
              {problems.map((p, i) => (
                <li key={i} className="flex gap-3 border-b px-4 py-1.5 text-[12.5px] last:border-b-0" style={{ borderColor: "var(--rule)" }}>
                  <span className="wire shrink-0" style={{ color: "var(--block)" }}>
                    {p.path || "file"}
                  </span>
                  <span>{p.message}</span>
                </li>
              ))}
            </ul>
          </Panel>
        )}

        <div className="flex items-center justify-between border-b" style={{ borderColor: "var(--rule)" }}>
          <div className="flex">
            {TABS.map((t) => (
              <button
                key={t.id}
                onClick={() => {
                  setTab(t.id);
                  setEditingYaml(t.id === "yaml");
                }}
                className="border-b-2 px-3 py-2 text-[13px]"
                style={{
                  borderColor: tab === t.id ? "var(--accent)" : "transparent",
                  color: tab === t.id ? "var(--ink)" : "var(--ink-muted)",
                  fontWeight: tab === t.id ? 600 : 400,
                  marginBottom: -1,
                }}
              >
                {t.label}
              </button>
            ))}
          </div>
          {dirty && (
            <span className="text-[12px]" style={{ color: "var(--monitor)" }}>
              Unsaved changes
            </span>
          )}
        </div>

        {tab === "yaml" && (
          <>
            <Notice tone="info">
              Editing the file directly keeps your comments and any settings the forms do not cover. The forms rewrite
              the whole file, which drops comments.
            </Notice>
            <div className="border" style={{ borderColor: "var(--rule)" }}>
              <CodeMirror
                value={yamlDraft}
                height="560px"
                extensions={[yamlLang()]}
                onChange={(v) => {
                  setYamlDraft(v);
                  setEditingYaml(true);
                }}
                basicSetup={{ lineNumbers: true, foldGutter: true, highlightActiveLine: true }}
              />
            </div>
          </>
        )}

        {tab === "services" && <Services draft={draft} setDraft={setDraft} extractors={detectors.data?.extractors ?? []} />}
        {tab === "rules" && <Rules draft={draft} setDraft={setDraft} detectors={detectors.data?.detectors ?? []} />}
        {tab === "allowlist" && <Exceptions draft={draft} setDraft={setDraft} />}
      </div>
    </Page>
  );
}

function update(draft: ConfigDoc, setDraft: (d: ConfigDoc) => void, mutate: (d: ConfigDoc) => void) {
  const next = structuredClone(draft);
  mutate(next);
  setDraft(next);
}

function Services({
  draft,
  setDraft,
  extractors,
}: {
  draft: ConfigDoc;
  setDraft: (d: ConfigDoc) => void;
  extractors: string[];
}) {
  const services = draft.services ?? [];
  const ruleIds = (draft.rules ?? []).map((r) => r.id);

  return (
    <div className="grid gap-4">
      <p className="max-w-[80ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
        A service says which destinations are decrypted and inspected, how their request bodies are read, and what
        happens when a rule stops one. Anything not listed here is tunnelled through without being decrypted.
      </p>
      {services.length === 0 && <Empty title="No services yet">Add one to start inspecting a destination.</Empty>}
      {services.map((svc, i) => (
        <Panel
          key={i}
          title={svc.name || "Unnamed service"}
          actions={
            <Button
              variant="danger"
              onClick={() => update(draft, setDraft, (d) => void (d.services as ServiceConfig[]).splice(i, 1))}
            >
              Remove
            </Button>
          }
        >
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Name">
              <TextInput value={svc.name} onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].name = v))} />
            </Field>
            <Field label="Reads request bodies as" hint="Pick the API shape this destination speaks.">
              <Select
                value={svc.extractor}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].extractor = v))}
                options={extractors.map((e) => ({ value: e, label: e }))}
              />
            </Field>
            <Field label="Destinations" hint="One regular expression per line, matched against the host name.">
              <TextArea
                value={(svc.hosts ?? []).join("\n")}
                mono
                rows={3}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].hosts = splitLines(v)))}
              />
            </Field>
            <Field label="Never inspected" hint="Paths that pass straight through, such as health probes.">
              <TextArea
                value={(svc.passthrough_paths ?? []).join("\n")}
                mono
                rows={3}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].passthrough_paths = splitLines(v)))}
              />
            </Field>
            <Field
              label="When a request is stopped"
              hint="A refusal is honest but shows as a generic error in the IDE. A stand-in reply tells the developer why."
            >
              <Select
                value={svc.block_mode}
                onChange={(v) => update(draft, setDraft, (d) => void (d.services[i].block_mode = v as "reject" | "synthetic"))}
                options={[
                  { value: "reject", label: "Refuse the request (403)" },
                  { value: "synthetic", label: "Reply with an explanation" },
                ]}
              />
            </Field>
            <Field label="Rules applied">
              <div className="flex flex-wrap gap-2 pt-1">
                {ruleIds.length === 0 && <span className="text-[12.5px]" style={{ color: "var(--ink-faint)" }}>Define a rule first.</span>}
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
        </Panel>
      ))}
      <div>
        <Button
          onClick={() =>
            update(draft, setDraft, (d) => {
              d.services = [
                ...(d.services ?? []),
                { name: "new-service", hosts: [], extractor: "generic", block_mode: "reject", rules: [] },
              ];
            })
          }
        >
          Add service
        </Button>
      </div>
    </div>
  );
}

function Rules({
  draft,
  setDraft,
  detectors,
}: {
  draft: ConfigDoc;
  setDraft: (d: ConfigDoc) => void;
  detectors: DetectorInfo[];
}) {
  const rules = draft.rules ?? [];
  return (
    <div className="grid gap-4">
      <p className="max-w-[80ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
        A rule groups what to look for with what to do about it. Start new rules on Record only, watch the Traffic view
        for a few days, then switch to Stop once the matches look right.
      </p>
      {rules.map((rule, i) => (
        <Panel
          key={i}
          title={rule.id || "Unnamed rule"}
          actions={
            <Button variant="danger" onClick={() => update(draft, setDraft, (d) => void (d.rules as RuleConfig[]).splice(i, 1))}>
              Remove
            </Button>
          }
        >
          <div className="grid gap-3">
            <div className="grid gap-3 md:grid-cols-3">
              <Field label="Name">
                <TextInput value={rule.id} onChange={(v) => update(draft, setDraft, (d) => void (d.rules[i].id = v))} />
              </Field>
              <Field label="Severity">
                <Select
                  value={rule.severity}
                  onChange={(v) => update(draft, setDraft, (d) => void (d.rules[i].severity = v as RuleConfig["severity"]))}
                  options={["low", "medium", "high", "critical"].map((s) => ({ value: s, label: s }))}
                />
              </Field>
              <Field label="When it matches">
                <Select
                  value={rule.action ?? ""}
                  onChange={(v) => update(draft, setDraft, (d) => void (d.rules[i].action = (v || undefined) as RuleConfig["action"]))}
                  options={[
                    { value: "", label: "Use the default" },
                    { value: "block", label: "Stop the request" },
                    { value: "monitor", label: "Record only" },
                    { value: "allow", label: "Ignore" },
                  ]}
                />
              </Field>
            </div>

            <Field label="Looks for">
              <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                {detectors.map((d) => {
                  const on = (rule.detectors ?? []).includes(d.id);
                  return (
                    <label key={d.id} className="flex items-start gap-2 text-[12.5px]" title={d.description}>
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={on}
                        onChange={() =>
                          update(draft, setDraft, (cfg) => {
                            const list = new Set(cfg.rules[i].detectors ?? []);
                            if (on) list.delete(d.id);
                            else list.add(d.id);
                            cfg.rules[i].detectors = [...list];
                          })
                        }
                      />
                      <span className="min-w-0">
                        <span className="wire block truncate">{d.id}</span>
                        <span className="block truncate" style={{ color: "var(--ink-faint)" }}>
                          {d.description}
                        </span>
                      </span>
                      <Severity level={d.severity} />
                    </label>
                  );
                })}
              </div>
            </Field>

            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Words and phrases" hint="One per line. Matched in prompts alongside the detectors above.">
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
              <Field label="Patterns" hint="One per line as name = expression, for anything the built-ins miss.">
                <TextArea
                  rows={4}
                  mono
                  value={(rule.regex ?? []).map((r) => `${r.id} = ${r.pattern}`).join("\n")}
                  onChange={(v) =>
                    update(draft, setDraft, (d) => {
                      d.rules[i].regex = splitLines(v).map((line) => {
                        const at = line.indexOf("=");
                        return at < 0
                          ? { id: line.trim(), pattern: "" }
                          : { id: line.slice(0, at).trim(), pattern: line.slice(at + 1).trim() };
                      });
                    })
                  }
                />
              </Field>
            </div>
          </div>
        </Panel>
      ))}
      <div>
        <Button
          onClick={() =>
            update(draft, setDraft, (d) => {
              d.rules = [...(d.rules ?? []), { id: "new-rule", severity: "medium", action: "monitor", detectors: [] }];
            })
          }
        >
          Add rule
        </Button>
      </div>
    </div>
  );
}

function Exceptions({ draft, setDraft }: { draft: ConfigDoc; setDraft: (d: ConfigDoc) => void }) {
  const al = draft.allowlist ?? {};
  const set = (key: string, value: unknown) =>
    update(draft, setDraft, (d) => {
      d.allowlist = { ...(d.allowlist ?? {}), [key]: value };
    });

  return (
    <div className="grid gap-4">
      <p className="max-w-[80ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
        Exceptions silence matches that are known to be safe. Use them to cut false alarms rather than turning a rule
        off entirely.
      </p>
      <Panel title="Values never flagged">
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Exact values" hint="Sample keys from documentation, test card numbers.">
            <TextArea rows={4} mono value={(al.values ?? []).join("\n")} onChange={(v) => set("values", splitLines(v))} />
          </Field>
          <Field label="Patterns" hint="One regular expression per line.">
            <TextArea rows={4} mono value={(al.patterns ?? []).join("\n")} onChange={(v) => set("patterns", splitLines(v))} />
          </Field>
          <Field label="Email domains" hint="Your own domains, so internal addresses are not treated as leaks.">
            <TextArea rows={3} mono value={(al.email_domains ?? []).join("\n")} onChange={(v) => set("email_domains", splitLines(v))} />
          </Field>
          <Field label="Parts of a prompt never scanned" hint="JSON paths, such as tool definitions the model sends every time.">
            <TextArea rows={3} mono value={(al.segment_paths ?? []).join("\n")} onChange={(v) => set("segment_paths", splitLines(v))} />
          </Field>
        </div>
      </Panel>
      <Panel title="Callers that skip inspection">
        <div className="grid gap-3 md:grid-cols-2">
          <Field label="Networks" hint="One CIDR block per line, for build agents and other trusted automation.">
            <TextArea rows={3} mono value={(al.client_cidrs ?? []).join("\n")} onChange={(v) => set("client_cidrs", splitLines(v))} />
          </Field>
          <Field
            label="Shared secret header"
            hint="A caller sending this header value skips inspection. Leave empty to disable."
          >
            <TextInput
              mono
              value={al.header_bypass?.token ?? ""}
              onChange={(v) => set("header_bypass", { name: al.header_bypass?.name ?? "X-AIGK-Bypass", token: v })}
            />
          </Field>
        </div>
      </Panel>
    </div>
  );
}

function TextArea({
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

function splitLines(v: string): string[] {
  return v
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}
