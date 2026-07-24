import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useAuth } from "./lib/store";
import { ToastContainer } from "./components/ui";
import { RouteErrorBoundary } from "./components/RouteErrorBoundary";
import { LoginPage } from "./pages/Login";
import { DashboardPage } from "./pages/Dashboard";
import { DatabaseOperationsPage } from "./pages/DatabaseOperations";
import { KeysPage } from "./pages/Keys";
import { KeyDetailPage } from "./pages/KeyDetail";
import { CryptoPage } from "./pages/Crypto";
import { PolicyPage } from "./pages/Policy";
import { AuditPage } from "./pages/Audit";
import { LifecyclePage } from "./pages/Lifecycle";
import { BatchCryptoPage } from "./pages/BatchCrypto";
import { EnvelopeConfigPage } from "./pages/EnvelopeConfig";

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
      <Route path="database" element={<RouteErrorBoundary><DatabaseOperationsPage /></RouteErrorBoundary>} />
      <Route path="keys" element={<RouteErrorBoundary><KeysPage /></RouteErrorBoundary>} />
      <Route path="keys/:id" element={<RouteErrorBoundary><KeyDetailPage /></RouteErrorBoundary>} />
      <Route path="crypto" element={<RouteErrorBoundary><CryptoPage /></RouteErrorBoundary>} />
      <Route path="batch-crypto" element={<RouteErrorBoundary><BatchCryptoPage /></RouteErrorBoundary>} />
      <Route path="lifecycle" element={<RouteErrorBoundary><LifecyclePage /></RouteErrorBoundary>} />
      <Route path="policy" element={<RouteErrorBoundary><PolicyPage /></RouteErrorBoundary>} />
      <Route path="audit" element={<RouteErrorBoundary><AuditPage /></RouteErrorBoundary>} />
      <Route path="envelope-config" element={<RouteErrorBoundary><EnvelopeConfigPage /></RouteErrorBoundary>} />
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
