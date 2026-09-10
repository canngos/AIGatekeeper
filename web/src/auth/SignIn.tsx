import { useState } from "react";
import { api } from "../api/client";
import { useSession } from "./session";
import { Button, Notice, TextInput } from "../components/primitives";

/**
 * The sign-in screen doubles as the setup screen: when no credential is
 * configured the API refuses to serve anything, so the page explains how to
 * create one rather than showing a form that cannot succeed.
 */
export function SignIn() {
  const { session, refresh } = useSession();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const configured = session?.auth_configured ?? true;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.login({ password });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "sign-in failed");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-full items-center justify-center p-6" style={{ background: "var(--ground)" }}>
      <div className="w-full max-w-[26rem]">
        <div className="mb-6 flex items-baseline gap-2">
          <Mark />
          <h1 className="text-[19px] font-semibold tracking-tight">AIGatekeeper</h1>
        </div>

        {configured ? (
          <form
            onSubmit={submit}
            className="border p-5"
            style={{ background: "var(--surface)", borderColor: "var(--rule)" }}
          >
            <label htmlFor="password" className="mb-1 block text-[12.5px] font-medium">
              Admin password
            </label>
            <TextInput id="password" name="password" type="password" value={password} onChange={setPassword} autoFocus />
            <div className="mt-4 flex items-center gap-3">
              <Button type="submit" variant="primary" disabled={busy || password.length === 0}>
                {busy ? "Signing in" : "Sign in"}
              </Button>
              <span className="text-[12px]" style={{ color: "var(--ink-faint)" }}>
                Version {session?.version ?? "unknown"}
              </span>
            </div>
            {error && (
              <div className="mt-4">
                <Notice tone="error">{error}</Notice>
              </div>
            )}
          </form>
        ) : (
          <div className="border p-5" style={{ background: "var(--surface)", borderColor: "var(--rule)" }}>
            <p className="text-[13px] font-medium">No admin credential is set yet</p>
            <p className="mt-2 text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
              The console stays closed until the proxy has one. Generate a hash on the host, add it to the
              configuration, and reload.
            </p>
            <pre
              className="wire mt-3 overflow-x-auto border p-3"
              style={{ background: "var(--surface-sunken)", borderColor: "var(--rule)" }}
            >{`aigatekeeper admin hash-password

# aigatekeeper.yaml
admin:
  auth:
    password_hash: "$2a$10$..."`}</pre>
            <p className="mt-3 text-[12.5px]" style={{ color: "var(--ink-muted)" }}>
              Setting AIGK_ADMIN_PASSWORD_HASH or AIGK_ADMIN_TOKEN in the environment works too.
            </p>
          </div>
        )}
      </div>
    </main>
  );
}

/** The gate: two posts and the wire passing between them. */
export function Mark({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 18 18" aria-hidden focusable="false">
      <path d="M3 2v14M15 2v14" stroke="var(--ink)" strokeWidth="1.6" strokeLinecap="square" />
      <path d="M3 9h4.5" stroke="var(--allow)" strokeWidth="1.6" />
      <path d="M10.5 9H15" stroke="var(--block)" strokeWidth="1.6" />
      <circle cx="9" cy="9" r="1.9" fill="none" stroke="var(--accent)" strokeWidth="1.6" />
    </svg>
  );
}
