import { CheckCircle2, RadioTower, RefreshCw, ShieldCheck } from "lucide-react";
import { AOSAssociationRow, formatObservedAt, WarningList } from "../components/ops/CCSDSRuntime";
import { useCCSDSStatus } from "../components/ops/queries";
import { EmptyState, ErrorState, Loading, PageContainer, Panel } from "../components";

export function AOSSecurityPage() {
  const query = useCCSDSStatus();
  const snapshot = query.data;
  const aosWarnings = snapshot?.warnings.filter((warning) => warning.startsWith("AOS_")) ?? [];
  const replayTracked = snapshot?.aos.filter((association) => association.replay_seen).length ?? 0;
  return (
    <PageContainer>
      <div className="page-header operations-header">
        <div>
          <div className="operations-kicker"><RadioTower size={13} />DOWNLINK RECEIVE POSTURE</div>
          <h1 className="section-title">AOS Downlink Operations</h1>
          <p className="section-subtitle">Active receive associations, authenticated replay high-water marks, and fail-closed frame release posture.</p>
        </div>
        <button className="operations-refresh" type="button" onClick={() => query.refetch()} disabled={query.isFetching}>
          <RefreshCw size={14} className={query.isFetching ? "spinning" : ""} />Refresh status
        </button>
      </div>
      {query.isLoading && <Loading label="Loading AOS downlink state..." />}
      {query.isError && <ErrorState message="AOS downlink status is unavailable." />}
      {snapshot && <>
        <div className="ops-metric-strip">
          <div><RadioTower size={17} /><span>Active associations</span><strong>{snapshot.aos.length}</strong></div>
          <div><ShieldCheck size={17} /><span>Replay tracking initialized</span><strong>{replayTracked}</strong></div>
          <div><CheckCircle2 size={17} /><span>Receive alerts</span><strong>{aosWarnings.length}</strong></div>
          <div><span>Last observation</span><strong>{formatObservedAt(snapshot.observed_at)}</strong></div>
        </div>

        <Panel title={`Active Receive Associations / ${snapshot.aos.length}`}>
          {snapshot.aos.length === 0 ? <EmptyState icon={<RadioTower size={24} />} message="No active AOS receive association is configured" /> : (
            <div className="table-scroll">
              <table className="data-table operations-table">
                <thead><tr><th>Direction</th><th>SPI</th><th>State</th><th>Suite</th><th>Replay window</th><th>Highest accepted sequence</th><th>IV / Tag</th></tr></thead>
                <tbody>{snapshot.aos.map((association) => <AOSAssociationRow key={association.id} association={association} />)}</tbody>
              </table>
            </div>
          )}
        </Panel>

        <div className="ops-dashboard-grid">
          <Panel title={`AOS Action Queue / ${aosWarnings.length}`}><WarningList warnings={aosWarnings} /></Panel>
          <Panel title="Release Discipline">
            <div className="ops-release-rules">
              <div><span>01</span><strong>Precheck</strong><small>Frame bounds, SPI, state, and replay eligibility</small></div>
              <div><span>02</span><strong>Cryptographic open</strong><small>Suite-bound authentication and decryption</small></div>
              <div><span>03</span><strong>Commit</strong><small>Advance replay state only after successful protection checks</small></div>
            </div>
          </Panel>
        </div>
      </>}
    </PageContainer>
  );
}
