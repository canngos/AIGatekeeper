import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SignIn } from "./SignIn";
import { SessionProvider } from "./session";
import { api } from "../api/client";
import type { Session } from "../api/types";

function renderSignIn(session: Partial<Session>) {
  vi.spyOn(api, "me").mockResolvedValue({
    authenticated: false,
    auth_configured: true,
    ui_built: true,
    version: "test",
    ...session,
  } as Session);
  return render(
    <SessionProvider>
      <SignIn />
    </SessionProvider>,
  );
}

beforeEach(() => vi.restoreAllMocks());

describe("SignIn", () => {
  it("signs in with a password and refreshes the session", async () => {
    const login = vi.spyOn(api, "login").mockResolvedValue({
      authenticated: true,
      auth_configured: true,
      ui_built: true,
      version: "test",
      csrf_token: "abc",
    });
    renderSignIn({});
    const user = userEvent.setup();

    await screen.findByLabelText("Admin password");
    await user.type(screen.getByLabelText("Admin password"), "hunter2hunter2");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(login).toHaveBeenCalledWith({ password: "hunter2hunter2" }));
  });

  it("shows the server's reason when the password is wrong", async () => {
    vi.spyOn(api, "login").mockRejectedValue(new Error("invalid credentials"));
    renderSignIn({});
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("Admin password"), "nope");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("invalid credentials");
  });

  it("explains how to create a credential when none is configured", async () => {
    renderSignIn({ auth_configured: false });
    expect(await screen.findByText("No admin credential is set yet")).toBeInTheDocument();
    expect(screen.getByText(/aigatekeeper admin hash-password/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Admin password")).not.toBeInTheDocument();
  });
});
