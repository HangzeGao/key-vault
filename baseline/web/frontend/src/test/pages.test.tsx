import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, HttpError } from "../lib/api";
import { DashboardPage } from "../pages/Dashboard";
import { DatabaseOperationsPage } from "../pages/DatabaseOperations";
import { AuditPage } from "../pages/Audit";
import { TCSecurityPage } from "../pages/TCSecurity";
import { AOSSecurityPage } from "../pages/AOSSecurity";
import { LoginPage } from "../pages/Login";
import { useAuth } from "../lib/store";

vi.mock("../lib/api", async (original) => {
  const actual = await original<typeof import("../lib/api")>();
  return { ...actual, api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() } };
});

const get = vi.mocked(api.get);
const emptyResponse = (path: string) => {
  if (path.endsWith("/ops/ccsds/status")) return {
    observed_at: new Date().toISOString(), status: "READY", ready: true, warnings: [],
    tc: {
      current: { id: "tc-current", spi: 4097, direction: "TC_TX", state: "CURRENT", suite_id: "SM4_HCTR", security_epoch: 5, key_version: 2, policy_version: 1, sequence_number_length: 0, transmitted_iv_length: 4, tag_length: 0, replay_window: 0, next_iv_counter: 42, replay_seen: false },
      next: { id: "tc-next", spi: 4098, direction: "TC_TX", state: "NEXT", suite_id: "SM4_HCTR", security_epoch: 6, key_version: 3, policy_version: 1, sequence_number_length: 0, transmitted_iv_length: 4, tag_length: 0, replay_window: 0, next_iv_counter: 0, replay_seen: false },
      recovery: { id: "tc-recovery", spi: 28673, direction: "TC_RECOVERY_TX", state: "ACTIVE", suite_id: "SM4_GCM", security_epoch: 0, key_version: 1, policy_version: 1, sequence_number_length: 0, transmitted_iv_length: 4, tag_length: 16, replay_window: 0, next_iv_counter: 3, replay_seen: false },
    },
    tc_rotation: { phase: "PREPARED", transaction_id: "9", current_spi: 4097, next_spi: 4098, current_root_version: 2, next_root_version: 3, evidence: "RECOVERY_FRAME_PRODUCED" },
    aos: [{ id: "aos-active", spi: 8193, direction: "AOS_RX", state: "ACTIVE", suite_id: "SM4_GCM", security_epoch: 0, key_version: 4, policy_version: 1, sequence_number_length: 4, transmitted_iv_length: 12, tag_length: 16, replay_window: 32, replay_highest: 88, replay_seen: true }],
  };
  if (path.endsWith("/ops/db/status")) return {
    driver: "sqlite", status: "ok", observed_at: new Date().toISOString(), connected: true,
    connection: { status: "ok", latency_ms: 3 },
    schema: { status: "ok", current: 1, expected: 1 },
    storage: { database_bytes: 4096, wal_bytes: 512, journal_mode: "WAL", synchronous: "FULL" },
    records: { security_associations: 4, audit_events: 12 },
    backup: { status: "operator_managed", rule: "restore only with a new operational SPI/epoch" },
    integrity: { status: "ok" },
  };
  if (path.includes("/audit/events")) return { events: [] };
  if (path.endsWith("/audit/chain/heads")) return { heads: [] };
  if (path.includes("/audit/chain/verify")) return { results: [] };
  return {};
};

const renderPage = (element: React.ReactNode) => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><MemoryRouter>{element}</MemoryRouter></QueryClientProvider>);
};

beforeEach(() => {
  useAuth.getState().logout();
  get.mockReset();
  get.mockImplementation(async (path) => emptyResponse(path) as never);
});

describe("operations console page contracts", () => {
  it.each([
    ["Mission Security Operations", <DashboardPage />],
    ["Security State", <DatabaseOperationsPage />],
    ["Security Audit", <AuditPage />],
    ["TC Uplink Operations", <TCSecurityPage />],
    ["AOS Downlink Operations", <AOSSecurityPage />],
  ])("renders %s", async (heading, page) => {
    renderPage(page);
    expect(await screen.findByRole("heading", { name: heading })).toBeInTheDocument();
  });

  it("renders live operational state without design or key-management controls", async () => {
    renderPage(<DashboardPage />);
    expect(await screen.findByText("Mission Security Operations")).toBeInTheDocument();
    expect(await screen.findByText("Security State Matrix")).toBeInTheDocument();
    expect(get.mock.calls.map(([path]) => path)).toContain("/ui/api/v1/ops/ccsds/status");
    expect(screen.queryByText(/DESIGN VIEW/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Switch convergence simulator/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Key Transfer/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Crypto Sandbox/i })).not.toBeInTheDocument();
  });

  it("database diagnostics do not request or render key inventory", async () => {
    renderPage(<DatabaseOperationsPage />);
    expect(get.mock.calls.map(([path]) => path)).toContain("/ui/api/v1/ops/db/status");
    expect(get.mock.calls.map(([path]) => path).some((path) => path.includes("/keys"))).toBe(false);
    expect(await screen.findByText("Persistence Boundary")).toBeInTheDocument();
  });

  it("validates console credentials before completing login", async () => {
    renderPage(<LoginPage />);
    fireEvent.change(screen.getByPlaceholderText("enter bearer token"), { target: { value: "valid-token" } });
    fireEvent.change(screen.getByPlaceholderText("t-default"), { target: { value: "t-default" } });
    fireEvent.click(screen.getByRole("button", { name: "Authenticate" }));
    await waitFor(() => expect(get).toHaveBeenCalledWith("/ui/api/v1/ops/ccsds/status"));
    expect(useAuth.getState().token).toBe("valid-token");
  });

  it("keeps invalid credentials on the login page", async () => {
    get.mockRejectedValueOnce(new HttpError(401, "AUTH_FAILED", "authentication failed", false));
    renderPage(<LoginPage />);
    fireEvent.change(screen.getByPlaceholderText("enter bearer token"), { target: { value: "invalid-token" } });
    fireEvent.click(screen.getByRole("button", { name: "Authenticate" }));
    expect(await screen.findByText("authentication failed or console access is not permitted")).toBeInTheDocument();
    expect(useAuth.getState().token).toBeNull();
  });

  it("fails closed on null operations collections instead of crashing the route", async () => {
    get.mockResolvedValueOnce({ ...emptyResponse("/ops/ccsds/status"), warnings: null } as never);
    renderPage(<DashboardPage />);
    expect(await screen.findByText("Mission status is unavailable. Verify Ops Plane reachability and identity scope.")).toBeInTheDocument();
  });
});
