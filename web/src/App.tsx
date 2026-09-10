import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { SessionProvider, useSession } from "./auth/session";
import { SignIn } from "./auth/SignIn";
import { Layout } from "./components/Layout";
import { Overview } from "./routes/Overview";
import { Traffic } from "./routes/Traffic";
import { People } from "./routes/People";
import { Policy } from "./routes/Policy";
import { Tester } from "./routes/Tester";
import { Status } from "./routes/Status";
import { UnauthorizedError } from "./api/client";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: (count, error) => !(error instanceof UnauthorizedError) && count < 2,
      refetchOnWindowFocus: false,
    },
  },
});

function Gate() {
  const { session, loading } = useSession();
  if (loading) {
    return <div className="p-6 text-[13px]" style={{ color: "var(--ink-muted)" }}>Loading</div>;
  }
  if (!session?.authenticated) return <SignIn />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="traffic" element={<Traffic />} />
        <Route path="people" element={<People />} />
        <Route path="policy" element={<Policy />} />
        <Route path="tester" element={<Tester />} />
        <Route path="status" element={<Status />} />
        <Route path="*" element={<Overview />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <SessionProvider>
          <Gate />
        </SessionProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
