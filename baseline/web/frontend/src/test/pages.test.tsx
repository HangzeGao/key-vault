import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, HttpError } from "../lib/api";
import { DashboardPage } from "../pages/Dashboard";
import { DatabaseOperationsPage } from "../pages/DatabaseOperations";
import { KeysPage } from "../pages/Keys";
import { CryptoPage } from "../pages/Crypto";
import { BatchCryptoPage } from "../pages/BatchCrypto";
import { AuditPage } from "../pages/Audit";
import { LifecyclePage } from "../pages/Lifecycle";
import { EnvelopeConfigPage } from "../pages/EnvelopeConfig";
import { PolicyPage } from "../pages/Policy";

vi.mock("../lib/api", async (original) => {
  const actual = await original<typeof import("../lib/api")>();
  return { ...actual, api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() } };
});

const get = vi.mocked(api.get);
const emptyResponse = (path: string) => {
  if (path.endsWith("/ui/api/v1/status")) return { database: { driver: "postgres", connected: true }, server: { listen_addr: ":8080", tpm_provider: "native", plane_isolation: "physical", uptime_seconds: 1 }, cluster: { cluster_epoch: 1 }, keys: { total: 0, active: 0, disabled: 0, destroy_pending: 0, destroyed: 0 } };
  if (path.endsWith("/keys")) return { keys: [] };
  if (path.endsWith("/ops/health")) return { overall: "ok", uptime_seconds: 1, checks: {} };
  if (path.endsWith("/ops/db/status")) return {
    driver: "postgres", status: "ok", observed_at: new Date().toISOString(), connected: true,
    connection: { status: "ok", latency_ms: 3 }, cluster_epoch: 1,
    runtime: { role: "primary", pool: { max: 20, total: 2, acquired: 1, idle: 1, acquire_wait_events: 0 }, schema: { status: "ok", current: 3, expected: 3 }, workload: { active_connections: 1, lock_waiters: 0, long_transactions: 0, oldest_transaction_ms: 5 } },
    capacity: { database_bytes: 4096, tables: [{ name: "keys", estimated_rows: 3, table_bytes: 2048, index_bytes: 1024 }] },
    data_protection: { replica_count: 0, replication_lag_ms: 0, backup_status: "managed_externally" },
    integrity: { status: "ok", orphan_key_versions: 0, destroyed_material_rows: 0, expired_active_dek_leases: 0, expired_active_nonce_leases: 0 },
    backlog: { lifecycle_failed: 0, lifecycle_pending: 0, outbox_pending: 0 },
    key_inventory: { scope: "global", total: 3, by_status: { ACTIVE: 2, DISABLED: 1 }, by_suite: { AES_256_GCM: 3 }, by_purpose: { encrypt_decrypt: 3 } },
    crk_consistency: {},
  };
  if (path.includes("/audit/events")) return { events: [] };
  if (path.endsWith("/audit/chain/heads")) return { heads: [] };
  if (path.includes("/audit/chain/verify")) return { results: [] };
  if (path.includes("/lifecycle/jobs")) return { jobs: [] };
  if (path.includes("/lifecycle/outbox")) return { events: [] };
  if (path.endsWith("/lifecycle/config")) return { owner_id: "worker", poll_interval: "5s", expiry_scan_interval: "1m", expiry_warning_window: "168h", lease_ttl: "30s", max_attempts: 5 };
  if (path.endsWith("/envelope/formats")) return { formats: [{ format_id: "configurable-json-v1", description: "configurable", match_rule: "json" }] };
  if (path.includes("/envelope-config")) return { tenant_id: "t-default", default_format: "configurable-json-v1", allowed_formats: ["configurable-json-v1"], profiles: [], version: 1, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), updated_by: "admin" };
  if (path.endsWith("/policies/signed")) return { policy_id: "p", version: 1, effective_at: new Date().toISOString(), status: "active", default_suite: "AES", suites: [], cryptoperiod: { default_days: 30, max_days: 90, rotate_before_days: 5 }, gray_rules: {}, signature: { alg: "Ed25519", key_id: "k", sig: "x".repeat(80), payload_hash: "h".repeat(64) } };
  return {};
};

const renderPage = (element: React.ReactNode) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter>{element}</MemoryRouter></QueryClientProvider>);
};

beforeEach(() => { get.mockReset(); get.mockImplementation(async (path) => emptyResponse(path) as never); });

describe("page contracts", () => {
  it.each([
    ["Dashboard", <DashboardPage />], ["Database Operations", <DatabaseOperationsPage />], ["Keys", <KeysPage />], ["Crypto Sandbox", <CryptoPage />],
    ["Batch Crypto", <BatchCryptoPage />], ["Audit Log", <AuditPage />], ["Lifecycle", <LifecyclePage />],
    ["Envelope Config", <EnvelopeConfigPage />], ["Policy", <PolicyPage />],
  ])("renders %s success/empty state", async (heading, page) => { renderPage(page); expect(await screen.findByRole("heading", { name: heading })).toBeInTheDocument(); });

  it("renders permission errors without blanking the route", async () => {
    get.mockRejectedValue(new HttpError(403, "PERMISSION_DENIED", "missing scope", false));
    renderPage(<KeysPage />); expect(await screen.findByText("missing scope")).toBeInTheDocument();
  });

  it("renders a large key list with long IDs", async () => {
    const keys = Array.from({ length: 120 }, (_, index) => ({ key_id: `key-${index}-${"x".repeat(80)}`, tenant_id: "t-default", name: `Key ${index}`, purpose: "encrypt_decrypt", suite_id: "AES", current_version: 1, status: "ACTIVE", tags: {}, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }));
    get.mockResolvedValue({ keys } as never); renderPage(<KeysPage />); expect(await screen.findByText("Key 119")).toBeInTheDocument();
  });

  it("visualizes only aggregate database inventory without listing management keys", async () => {
    renderPage(<DatabaseOperationsPage />);
    expect(get.mock.calls.map(([path]) => path)).toContain("/ui/api/v1/ops/db/status");
    expect(get.mock.calls.map(([path]) => path)).not.toContain("/ui/api/v1/keys");
    expect(await screen.findByText(/global aggregate/)).toBeInTheDocument();
    expect(await screen.findByText("Key status distribution")).toBeInTheDocument();
    expect(await screen.findByText("Key workloads")).toBeInTheDocument();
    expect(await screen.findByText("AES_256_GCM")).toBeInTheDocument();
  });
});
