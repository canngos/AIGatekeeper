import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import CodeMirror from "@uiw/react-codemirror";
import { yaml as yamlLang } from "@codemirror/lang-yaml";
import { api } from "../api/client";
import type { ConfigDoc, Problem } from "../api/types";
import { Page } from "../components/Layout";
import { Button, Notice, Panel } from "../components/primitives";
import { Services } from "../policy/Services";
import { Rules } from "../policy/Rules";
import { Exceptions } from "../policy/Exceptions";

type Mode = "guided" | "file";

export function Policy() {
  const qc = useQueryClient();
  const config = useQuery({ queryKey: ["config"], queryFn: api.config });
  const detectors = useQuery({ queryKey: ["detectors"], queryFn: api.detectors });

  const [mode, setMode] = useState<Mode>("guided");
  const [draft, setDraft] = useState<ConfigDoc | null>(null);
  const [yamlDraft, setYamlDraft] = useState<string>("");
  const [problems, setProblems] = useState<Problem[]>([]);
  const [status, setStatus] = useState<{ tone: "ok" | "error" | "info"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (config.data) {
      setDraft(structuredClone(config.data.config));
      setYamlDraft(config.data.yaml);
    }
  }, [config.data]);

  const guidedDirty = useMemo(
    () => Boolean(config.data && draft && JSON.stringify(draft) !== JSON.stringify(config.data.config)),
    [config.data, draft],
  );
  const fileDirty = Boolean(config.data && yamlDraft !== config.data.yaml);
  const dirty = mode === "file" ? fileDirty : guidedDirty;

  function payload() {
    return mode === "file" ? { yaml: yamlDraft } : { config: draft };
  }

  /**
   * The two editors are two views of one policy, so switching carries the
   * work across rather than discarding it. The forms rewrite the file from
   * the schema and cannot keep comments, so an untouched policy switches by
   * showing the file exactly as it is on disk instead.
   */
  async function switchMode(next: Mode) {
    if (next === mode) return;
    setStatus(null);
    setProblems([]);
    if (next === "file") {
      if (!guidedDirty) {
        setYamlDraft(config.data?.yaml ?? "");
        setMode("file");
        return;
      }
      setBusy(true);
      try {
        const res = await api.validateConfig({ config: draft });
        if (res.yaml) setYamlDraft(res.yaml);
        setProblems(res.errors ?? []);
        setMode("file");
        setStatus({ tone: "info", text: "Your changes were written into the file. Comments in the sections you edited are gone." });
      } catch (err) {
        setStatus({ tone: "error", text: err instanceof Error ? err.message : "Could not read the policy" });
      } finally {
        setBusy(false);
      }
      return;
    }
    if (!fileDirty) {
      setMode("guided");
      return;
    }
    setBusy(true);
    try {
      const res = await api.validateConfig({ yaml: yamlDraft });
      if (!res.ok || !res.config) {
        setProblems(res.errors ?? []);
        setStatus({ tone: "error", text: "The file has problems, so the forms cannot show it. Fix these first." });
        return;
      }
      setDraft(res.config);
      setMode("guided");
    } catch (err) {
      setStatus({ tone: "error", text: err instanceof Error ? err.message : "Could not read the file" });
    } finally {
      setBusy(false);
    }
  }

  async function validate() {
    setBusy(true);
    setStatus(null);
    try {
      const res = await api.validateConfig(payload());
      setProblems(res.errors ?? []);
      setStatus(
        res.ok
          ? { tone: "ok", text: "This policy is valid and ready to apply." }
          : { tone: "error", text: "This policy has problems that must be fixed before it can be applied." },
      );
    } catch (err) {
      setStatus({ tone: "error", text: err instanceof Error ? err.message : "The check could not run" });
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
          ? "Someone else changed the policy while you were editing. Reload to see their version, then make your changes again."
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
      description={`What the proxy inspects and what it stops. Saved to ${config.data?.path} and picked up without a restart.`}
      actions={
        <>
          <ModeSwitch mode={mode} onChange={(m) => void switchMode(m)} disabled={busy} />
          <Button onClick={() => void validate()} disabled={busy}>
            Check
          </Button>
          <Button variant="primary" onClick={() => void apply()} disabled={busy || !dirty}>
            {busy ? "Working" : "Apply changes"}
          </Button>
        </>
      }
    >
      <div className="grid gap-5">
        {dirty && (
          <Notice tone="info">
            Unsaved changes. Nothing reaches the proxy until you choose Apply changes.
          </Notice>
        )}
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

        <Enforcement draft={draft} setDraft={setDraft} />

        {mode === "file" ? (
          <div className="grid gap-2">
            <p className="max-w-[78ch] text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
              The file as the proxy reads it. Editing here keeps your comments and reaches settings the forms do not
              cover, such as listeners, alerting and identity.
            </p>
            <div className="border" style={{ borderColor: "var(--rule)" }}>
              <CodeMirror
                value={yamlDraft}
                height="560px"
                extensions={[yamlLang()]}
                onChange={setYamlDraft}
                basicSetup={{ lineNumbers: true, foldGutter: true, highlightActiveLine: true }}
              />
            </div>
          </div>
        ) : (
          <>
            <Services draft={draft} setDraft={setDraft} extractors={detectors.data?.extractors ?? []} />
            <Rules draft={draft} setDraft={setDraft} detectors={detectors.data?.detectors ?? []} />
            <Exceptions draft={draft} setDraft={setDraft} />
          </>
        )}
      </div>
    </Page>
  );
}

function ModeSwitch({ mode, onChange, disabled }: { mode: Mode; onChange: (m: Mode) => void; disabled?: boolean }) {
  return (
    <div className="flex border" style={{ borderColor: "var(--rule-strong)" }} role="group" aria-label="Editor">
      {(["guided", "file"] as Mode[]).map((m) => (
        <button
          key={m}
          type="button"
          disabled={disabled}
          onClick={() => onChange(m)}
          aria-pressed={mode === m}
          className="px-2.5 py-1 text-[13px] font-medium disabled:opacity-45"
          style={{
            background: mode === m ? "var(--accent)" : "var(--surface)",
            color: mode === m ? "var(--accent-ink)" : "var(--ink-muted)",
          }}
        >
          {m === "guided" ? "Forms" : "File"}
        </button>
      ))}
    </div>
  );
}

/**
 * Whether the policy actually stops anything.
 *
 * This is one line in the file and it decides whether the whole policy has
 * teeth, so it belongs at the top of the page rather than three levels into
 * a form. A policy that looks fully configured while quietly forwarding
 * everything is the failure worth designing against.
 */
function Enforcement({ draft, setDraft }: { draft: ConfigDoc; setDraft: (d: ConfigDoc) => void }) {
  const monitor = Boolean(draft.mode?.monitor);
  const services = draft.services ?? [];
  const active = services.filter((s) => s.enabled !== false).length;
  const rules = draft.rules ?? [];
  const stopping = rules.filter((r) => (r.action ?? draft.default_action) === "block").length;

  const set = (v: boolean) =>
    setDraft({ ...structuredClone(draft), mode: { ...(draft.mode ?? { monitor: false }), monitor: v } });

  return (
    <section className="border" style={{ background: "var(--surface)", borderColor: monitor ? "var(--monitor)" : "var(--rule)" }}>
      <div className="flex flex-wrap items-start justify-between gap-4 p-3">
        <div>
          <div className="flex items-center gap-4">
            <span className="text-[13px] font-semibold">Enforcement</span>
            {[
              { v: false, label: "Blocking" },
              { v: true, label: "Watch only" },
            ].map((o) => (
              <label key={String(o.v)} className="flex items-center gap-1.5 text-[12.5px]">
                <input type="radio" name="enforcement" checked={monitor === o.v} onChange={() => set(o.v)} />
                {o.label}
              </label>
            ))}
          </div>
          <p className="mt-1 max-w-[70ch] text-[12px]" style={{ color: monitor ? "var(--monitor)" : "var(--ink-faint)" }}>
            {monitor
              ? "Nothing is being stopped. Every match is still detected, recorded and alerted on, but the request goes through. Right for a rollout, wrong for testing that blocking works."
              : "Matching prompts are stopped before they reach the model."}
          </p>
        </div>
        <dl className="flex gap-6 text-[12.5px]">
          <div>
            <dt style={{ color: "var(--ink-faint)" }}>Inspected</dt>
            <dd className="text-[15px] font-semibold">
              {active}
              {active < services.length && (
                <span className="ml-1.5 text-[12px] font-normal" style={{ color: "var(--monitor)" }}>
                  {services.length - active} off
                </span>
              )}
            </dd>
          </div>
          <div>
            <dt style={{ color: "var(--ink-faint)" }}>Rules</dt>
            <dd className="text-[15px] font-semibold">{rules.length}</dd>
          </div>
          <div>
            <dt style={{ color: "var(--ink-faint)" }}>Of those, stopping</dt>
            <dd className="text-[15px] font-semibold">{stopping}</dd>
          </div>
        </dl>
      </div>
    </section>
  );
}
