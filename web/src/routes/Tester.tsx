import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { TestResponse } from "../api/types";
import { Page } from "../components/Layout";
import {
  Button,
  DecisionMark,
  Empty,
  Field,
  Notice,
  Panel,
  Select,
  Severity,
  actionColor,
  actionLabel,
} from "../components/primitives";

const SAMPLES: { label: string; text: string }[] = [
  {
    label: "AWS credentials in a config file",
    text: `Why does this fail?\n\n[default]\naws_access_key_id = AKIAIOSFODNN7REALKEY\naws_secret_access_key = 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`,
  },
  {
    label: "A private key pasted into a prompt",
    text: `Can you explain this key format?\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AH6M\n-----END RSA PRIVATE KEY-----`,
  },
  {
    label: "Customer data in a support question",
    text: `Draft a refund email for card 4111 1111 1111 1111, contact alice.smith@customer.example`,
  },
  {
    label: "An ordinary question",
    text: "Refactor this function to use a context and return early on error.",
  },
];

export function Tester() {
  const [mode, setMode] = useState<"text" | "body">("text");
  const [text, setText] = useState(SAMPLES[0].text);
  const [body, setBody] = useState(
    `{"model":"gpt-4o","messages":[{"role":"user","content":"my key is AKIAIOSFODNN7REALKEY"}]}`,
  );
  const [service, setService] = useState("");
  const [result, setResult] = useState<TestResponse | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const config = useQuery({ queryKey: ["config"], queryFn: api.config });
  const services = config.data?.config.services ?? [];

  async function run() {
    setBusy(true);
    setError("");
    try {
      setResult(
        await api.test(
          mode === "text" ? { text, service: service || undefined } : { body, service: service || undefined },
        ),
      );
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "The check failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Page
      title="Tester"
      description="Run text or a captured request through the live policy without sending anything to a provider."
    >
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="grid gap-4">
          <Panel
            title="What to check"
            actions={
              <div className="flex border" style={{ borderColor: "var(--rule-strong)" }}>
                {(["text", "body"] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className="px-2.5 py-0.5 text-[12.5px]"
                    style={{
                      background: mode === m ? "var(--accent-soft)" : "transparent",
                      fontWeight: mode === m ? 600 : 400,
                    }}
                  >
                    {m === "text" ? "Prompt text" : "Request body"}
                  </button>
                ))}
              </div>
            }
          >
            <div className="grid gap-3">
              {mode === "text" ? (
                <>
                  <textarea
                    value={text}
                    rows={10}
                    onChange={(e) => setText(e.target.value)}
                    className="w-full border px-2 py-1.5 text-[13px]"
                    style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                    aria-label="Prompt text"
                  />
                  <div className="flex flex-wrap gap-2">
                    {SAMPLES.map((s) => (
                      <Button key={s.label} variant="quiet" onClick={() => setText(s.text)}>
                        {s.label}
                      </Button>
                    ))}
                  </div>
                </>
              ) : (
                <textarea
                  value={body}
                  rows={12}
                  onChange={(e) => setBody(e.target.value)}
                  className="wire w-full border px-2 py-1.5"
                  style={{ background: "var(--surface)", borderColor: "var(--rule-strong)" }}
                  aria-label="Request body"
                />
              )}

              <Field
                label="Evaluate as"
                hint={
                  service
                    ? "Only the rules attached to this service run."
                    : "Every rule in the policy runs, which is the widest check."
                }
              >
                <Select
                  value={service}
                  onChange={setService}
                  options={[
                    { value: "", label: "Every rule in the policy" },
                    ...services.map((s) => ({ value: s.name, label: s.name })),
                  ]}
                />
              </Field>

              <div>
                <Button variant="primary" onClick={() => void run()} disabled={busy}>
                  {busy ? "Checking" : "Check against the policy"}
                </Button>
              </div>
            </div>
          </Panel>
        </div>

        <div className="grid gap-4">
          {error && <Notice tone="error">{error}</Notice>}
          {!result && !error && (
            <Panel>
              <Empty title="Nothing checked yet">
                Paste a prompt a developer might send, or a captured request body, and see what the policy would do
                with it.
              </Empty>
            </Panel>
          )}
          {result && <Outcome result={result} />}
        </div>
      </div>
    </Page>
  );
}

function Outcome({ result }: { result: TestResponse }) {
  const { decision, findings, extraction } = result;
  return (
    <>
      <Panel>
        <div className="flex items-center gap-3">
          <DecisionMark action={decision.action} />
          <div>
            <p className="text-[15px] font-semibold" style={{ color: actionColor(decision.action) }}>
              {actionLabel(decision.action)}
            </p>
            <p className="text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
              {decision.action === "allow"
                ? "Nothing in this prompt matched the policy."
                : `Rule ${decision.rule} matched${decision.detectors.length ? ` on ${decision.detectors.join(", ")}` : ""}.`}
            </p>
          </div>
        </div>
        {result.warning && (
          <div className="mt-3">
            <Notice tone="error">{result.warning}</Notice>
          </div>
        )}
      </Panel>

      {findings.length > 0 && (
        <Panel title={`${findings.length} ${findings.length === 1 ? "match" : "matches"}`} flush>
          <table className="w-full text-[12.5px]">
            <thead>
              <tr style={{ color: "var(--ink-faint)" }}>
                <th className="px-4 py-1.5 text-left font-medium">What was found</th>
                <th className="px-4 py-1.5 text-left font-medium">Severity</th>
                <th className="px-4 py-1.5 text-left font-medium">Where</th>
                <th className="px-4 py-1.5 text-left font-medium">Match</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i} className="border-t" style={{ borderColor: "var(--rule)" }}>
                  <td className="wire px-4 py-1.5">{f.detector}</td>
                  <td className="px-4 py-1.5">
                    <Severity level={f.severity} />
                  </td>
                  <td className="wire px-4 py-1.5" style={{ color: "var(--ink-muted)" }}>
                    {f.segment}
                  </td>
                  <td className="wire px-4 py-1.5">{f.preview}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      <Panel title="What the policy read" flush>
        {extraction.segments.length === 0 ? (
          <Empty title="No prompt text was found in this request" />
        ) : (
          <ul>
            {extraction.segments.map((s, i) => (
              <li key={i} className="border-b px-4 py-2 last:border-b-0" style={{ borderColor: "var(--rule)" }}>
                <div className="flex items-baseline gap-2">
                  <span className="wire" style={{ color: "var(--ink-faint)" }}>
                    {s.path}
                  </span>
                  {s.role && (
                    <span className="text-[11px]" style={{ color: "var(--ink-muted)" }}>
                      {s.role}
                    </span>
                  )}
                </div>
                <p className="mt-0.5 max-h-24 overflow-y-auto whitespace-pre-wrap text-[12.5px]">{s.text}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  );
}
