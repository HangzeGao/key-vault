import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAuth } from "./lib/store";
import { ToastContainer } from "./components/ui";
import { RouteErrorBoundary } from "./components/RouteErrorBoundary";
import { LoginPage } from "./pages/Login";
import { DashboardPage } from "./pages/Dashboard";
import { SystemAuditPage } from "./pages/SystemAudit";
import { TCSecurityPage } from "./pages/TCSecurity";
import { AOSSecurityPage } from "./pages/AOSSecurity";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

function ProtectedRoutes() {
  const token = useAuth((s) => s.token);
  if (!token) return <Navigate to="/ui/login" replace />;

  return (
    <Routes>
      <Route path="dashboard" element={<RouteErrorBoundary><DashboardPage /></RouteErrorBoundary>} />
      <Route path="tc-security" element={<RouteErrorBoundary><TCSecurityPage /></RouteErrorBoundary>} />
      <Route path="aos-security" element={<RouteErrorBoundary><AOSSecurityPage /></RouteErrorBoundary>} />
      <Route path="system" element={<RouteErrorBoundary><SystemAuditPage /></RouteErrorBoundary>} />
      <Route path="*" element={<Navigate to="dashboard" replace />} />
    </Routes>
  );
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/ui/login" element={<LoginPage />} />
          <Route path="/ui/*" element={<ProtectedRoutes />} />
          <Route path="*" element={<Navigate to="/ui/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
      <ToastContainer />
    </QueryClientProvider>
  );
}
