import { NavLink, Outlet } from "react-router-dom";
import { useSession } from "../auth/session";
import { Mark } from "../auth/SignIn";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/traffic", label: "Traffic" },
  { to: "/policy", label: "Policy" },
  { to: "/tester", label: "Tester" },
  { to: "/status", label: "Status" },
];

export function Layout() {
  const { session, signOut } = useSession();
  return (
    <div className="flex min-h-full" style={{ background: "var(--ground)" }}>
      <nav
        className="flex w-[168px] shrink-0 flex-col border-r"
        style={{ background: "var(--surface)", borderColor: "var(--rule)" }}
      >
        <div className="flex items-center gap-2 px-4 py-4">
          <Mark />
          <span className="text-[14px] font-semibold tracking-tight">AIGatekeeper</span>
        </div>
        <ul className="flex-1 px-2">
          {NAV.map((item) => (
            <li key={item.to}>
              <NavLink
                to={item.to}
                end={item.end}
                className="block px-2 py-1.5 text-[13px]"
                style={({ isActive }) => ({
                  color: isActive ? "var(--ink)" : "var(--ink-muted)",
                  fontWeight: isActive ? 600 : 400,
                  background: isActive ? "var(--accent-soft)" : "transparent",
                  borderLeft: `2px solid ${isActive ? "var(--accent)" : "transparent"}`,
                })}
              >
                {item.label}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="border-t px-4 py-3 text-[12px]" style={{ borderColor: "var(--rule)", color: "var(--ink-faint)" }}>
          <div className="mb-2">Version {session?.version}</div>
          <button onClick={() => void signOut()} className="underline underline-offset-2">
            Sign out
          </button>
        </div>
      </nav>
      <main className="min-w-0 flex-1">
        <Outlet />
      </main>
    </div>
  );
}

export function Page({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="mx-auto max-w-[1180px] p-6">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-[21px] font-semibold tracking-tight">{title}</h1>
          {description && (
            <p className="mt-0.5 max-w-[70ch] text-[13px]" style={{ color: "var(--ink-muted)" }}>
              {description}
            </p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </header>
      {children}
    </div>
  );
}
