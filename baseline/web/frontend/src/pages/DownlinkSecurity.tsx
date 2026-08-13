import { RadioTower, RefreshCw, ShieldCheck } from "lucide-react";
import { formatObservedAt, WarningList } from "../components/ops/CCSDSRuntime";
import { useCCSDSStatus } from "../components/ops/queries";
import { ErrorState, Loading, PageContainer, Panel } from "../components";

export function DownlinkSecurityPage() {
  const query = useCCSDSStatus();
  const snapshot = query.data;
  return (
    <PageContainer>
      <div className="page-header operations-header">
        <div>
          <div className="operations-kicker"><RadioTower size={13} />DOWNLINK CRYPTO POSTURE</div>
          <h1 className="section-title">Raw Downlink</h1>
          <p className="section-subtitle">SM4-GCM hardware ciphertext release using the Current / Previous DEK batches.</p>
        </div>
        <button className="operations-refresh" type="button" onClick={() => query.refetch()} disabled={query.isFetching}>
          <RefreshCw size={14} className={query.isFetching ? "spinning" : ""} />Refresh status
        </button>
      </div>
      {query.isLoading && <Loading label="Loading raw downlink state..." />}
      {query.isError && <ErrorState message="Raw downlink status is unavailable." />}
      {snapshot && <>
        <section className="ops-format-notice" role="status">
          <div><strong>FORMAT STATUS</strong><span>{snapshot.downlink_format}</span></div>
          <p>A future AOS adapter may carry these bytes. It must not create another key lifecycle or reinterpret the authenticated raw package.</p>
        </section>
        <div className="ops-metric-strip">
          <div><RadioTower size={17} /><span>Input contract</span><strong>RAW</strong></div>
          <div><ShieldCheck size={17} /><span>Protection</span><strong>SM4-GCM</strong></div>
          <div><span>Active KEK slot</span><strong>{snapshot.downlink.provisioned ? snapshot.downlink.active_kek_slot : "--"}</strong></div>
          <div><span>Current generation</span><strong>{snapshot.downlink.current_generation || "--"}</strong></div>
        </div>
        <div className="ops-dashboard-grid">
          <Panel title={`Shared Action Queue / ${snapshot.warnings.length}`}><WarningList warnings={snapshot.warnings} /></Panel>
          <Panel title="Fixed Runtime Contract">
            <div className="ops-release-rules">
              <div><span>01</span><strong>Select</strong><small>16-bit key serial selects one of 1,024 DEKs</small></div>
              <div><span>02</span><strong>Authenticate</strong><small>Current first; Previous once only after Current fails</small></div>
              <div><span>03</span><strong>Release</strong><small>Plaintext is returned only after a valid 16-byte GCM tag</small></div>
            </div>
          </Panel>
          <Panel title="Batch Lifecycle">
            <div className="ops-release-rules">
              <div><span>C</span><strong>Current / {snapshot.downlink.current_generation || "--"}</strong><small>{snapshot.downlink.current_observed ? "Observed by authenticated downlink" : "Not observed; next generation blocked"}</small></div>
              <div><span>P</span><strong>Previous / {snapshot.downlink.previous_generation || "--"}</strong><small>Single authentication fallback only</small></div>
              <div><span>T</span><strong>Updated</strong><small>{formatObservedAt(snapshot.observed_at)}</small></div>
            </div>
          </Panel>
        </div>
      </>}
    </PageContainer>
  );
}
