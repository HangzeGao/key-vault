import { Activity, ArrowUpRight, Database, RadioTower, RefreshCw, Satellite, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { ErrorState, Loading, PageContainer, Panel } from "../components";
import { useCCSDSStatus } from "../components/ops/queries";
import { formatCounter, formatObservedAt, formatSPI, statusTone, WarningList } from "../components/ops/CCSDSRuntime";
import { SignalPill } from "../components/ops/widgets";

export function DashboardPage() {
  const query = useCCSDSStatus();
  const snapshot = query.data;

  return (
    <PageContainer>
      <div className="page-header operations-header">
        <div>
          <div className="operations-kicker"><Activity size={13} />MISSION CONTROL / LIVE STATUS</div>
          <h1 className="section-title">Mission Security Operations</h1>
          <p className="section-subtitle">Operational readiness for TC uplink, raw downlink, Recovery GCM, and durable ground state.</p>
        </div>
        <button className="operations-refresh" type="button" onClick={() => query.refetch()} disabled={query.isFetching}>
          <RefreshCw size={14} className={query.isFetching ? "spinning" : ""} />Refresh status
        </button>
      </div>

      {query.isLoading && <Loading label="Loading mission security status..." />}
      {query.isError && <ErrorState message="Mission status is unavailable. Verify Ops Plane reachability and identity scope." />}
      {snapshot && <>
        <section className={`ops-status-board ${snapshot.status.toLowerCase()}`} aria-label="Mission readiness">
          <div className="ops-status-primary">
            <ShieldCheck size={28} />
            <div><span>Mission posture</span><strong>{snapshot.status}</strong></div>
          </div>
          <div className="ops-status-meta"><span>Decision</span><SignalPill label={snapshot.ready ? "GO" : "HOLD"} tone={statusTone(snapshot.status)} /></div>
          <div className="ops-status-meta"><span>Open alerts</span><strong>{snapshot.warnings.length}</strong></div>
          <div className="ops-status-meta observed"><span>Observed</span><strong>{formatObservedAt(snapshot.observed_at)}</strong></div>
        </section>

        <div className="operations-stat-grid">
          <Link to="/ui/tc-security" className="operations-stat-card">
            <Satellite size={18} /><span>TC CURRENT</span><strong>{formatSPI(snapshot.tc.current?.spi)}</strong><small>Next IV {formatCounter(snapshot.tc.current?.next_iv_counter)}</small><ArrowUpRight className="ops-card-arrow" size={14} />
          </Link>
          <Link to="/ui/tc-security" className="operations-stat-card">
            <Satellite size={18} /><span>TC NEXT</span><strong>{formatSPI(snapshot.tc.next?.spi)}</strong><small>{snapshot.tc.next ? `Epoch ${snapshot.tc.next.security_epoch} staged` : "Not staged"}</small><ArrowUpRight className="ops-card-arrow" size={14} />
          </Link>
          <Link to="/ui/tc-security" className="operations-stat-card recovery">
            <ShieldCheck size={18} /><span>RECOVERY GCM</span><strong>{formatSPI(snapshot.tc.recovery?.spi)}</strong><small>{snapshot.tc.recovery?.suite_id ?? "Not configured"}</small><ArrowUpRight className="ops-card-arrow" size={14} />
          </Link>
          <Link to="/ui/downlink-security" className="operations-stat-card downlink">
            <RadioTower size={18} /><span>RAW DOWNLINK</span><strong>1,024</strong><small>{snapshot.downlink_format}</small><ArrowUpRight className="ops-card-arrow" size={14} />
          </Link>
        </div>

        <div className="ops-dashboard-grid">
          <Panel title={`Action Queue / ${snapshot.warnings.length}`}><WarningList warnings={snapshot.warnings} /></Panel>
          <Panel title="Security State Matrix">
            <div className="ops-state-matrix">
              <div><span>TC Current</span><strong>{snapshot.tc.current?.state ?? "MISSING"}</strong><small>{formatSPI(snapshot.tc.current?.spi)}</small></div>
              <div><span>TC Next</span><strong>{snapshot.tc.next?.state ?? "MISSING"}</strong><small>{formatSPI(snapshot.tc.next?.spi)}</small></div>
              <div><span>Recovery</span><strong>{snapshot.tc.recovery?.state ?? "MISSING"}</strong><small>{formatSPI(snapshot.tc.recovery?.spi)}</small></div>
              <div><span>Raw Downlink</span><strong>{snapshot.downlink_format}</strong><small>Current / Previous batch fallback</small></div>
            </div>
          </Panel>
          <Panel title="Ground / Flight Reconciliation">
            <div className="ops-state-matrix">
              <div><span>Profile digest</span><strong>{snapshot.flight_reconciliation}</strong><small>{snapshot.profile_digest.slice(0, 16)}&hellip;</small></div>
              <div><span>Flight self-test</span><strong>{snapshot.flight?.self_test ?? "NOT OBSERVED"}</strong><small>{snapshot.flight?.crypto_backend ?? "No backend evidence"}</small></div>
              <div><span>Flight TC state</span><strong>{snapshot.flight ? formatSPI(snapshot.flight.current_spi) : "--"}</strong><small>{snapshot.flight ? `Epoch ${snapshot.flight.security_epoch} / root v${snapshot.flight.root_version}` : "No housekeeping status"}</small></div>
              <div><span>Flight processing</span><strong>{snapshot.flight ? `${snapshot.flight.max_receive_us.toLocaleString("en-US")} µs max` : "--"}</strong><small>{snapshot.flight ? `${snapshot.flight.cycle_limit_exceeded_count} cycle overruns` : "No timing evidence"}</small></div>
            </div>
          </Panel>
        </div>

        <section className="ops-guardrail">
          <Database size={18} />
          <div><strong>Read-only operational projection</strong><span>This console cannot change roots, keys, SPIs, IV counters, replay windows, or switch state. Protocol state transitions remain inside the CCSDS module.</span></div>
          <Link to="/ui/system">Inspect system & audit <ArrowUpRight size={13} /></Link>
        </section>
      </>}
    </PageContainer>
  );
}
