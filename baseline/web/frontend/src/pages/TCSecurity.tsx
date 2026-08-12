import { ArrowRight, RefreshCw, Satellite, ShieldCheck } from "lucide-react";
import { AssociationCard, formatCounter, formatObservedAt, TC_COUNTER_CAPACITY, WarningList } from "../components/ops/CCSDSRuntime";
import { useCCSDSStatus } from "../components/ops/queries";
import { ErrorState, Loading, PageContainer, Panel } from "../components";

function remaining(counter?: number) {
  return counter === undefined ? "--" : formatCounter(TC_COUNTER_CAPACITY - counter);
}

export function TCSecurityPage() {
  const query = useCCSDSStatus();
  const snapshot = query.data;
  const tcWarnings = snapshot?.warnings.filter((warning) => warning.startsWith("TC_")) ?? [];
  return (
    <PageContainer>
      <div className="page-header operations-header">
        <div>
          <div className="operations-kicker"><Satellite size={13} />UPLINK CONTINUITY</div>
          <h1 className="section-title">TC Uplink</h1>
          <p className="section-subtitle">Live ordinary and recovery transmit associations, epoch staging, and durable 32-bit IV allocation.</p>
        </div>
        <button className="operations-refresh" type="button" onClick={() => query.refetch()} disabled={query.isFetching}>
          <RefreshCw size={14} className={query.isFetching ? "spinning" : ""} />Refresh status
        </button>
      </div>
      {query.isLoading && <Loading label="Loading TC uplink state..." />}
      {query.isError && <ErrorState message="TC uplink status is unavailable." />}
      {snapshot && <>
        <div className="ops-page-meta"><span>Observed {formatObservedAt(snapshot.observed_at)}</span><strong>{tcWarnings.length === 0 ? "UPLINK READY" : `${tcWarnings.length} UPLINK ALERTS`}</strong></div>

        <div className="association-grid">
          <AssociationCard title="ORDINARY / CURRENT" association={snapshot.tc.current} counter />
          <AssociationCard title="ORDINARY / NEXT" association={snapshot.tc.next} counter />
          <AssociationCard title="RECOVERY GCM / ACTIVE" association={snapshot.tc.recovery} counter />
        </div>

        <div className="ops-dashboard-grid tc-continuity-grid">
          <Panel title="Automatic Epoch Continuity">
            <div className="ops-continuity-flow">
              <div className={snapshot.tc.current ? "available" : "missing"}><span>1</span><strong>Current</strong><small>Protect complete TC frames</small></div>
              <ArrowRight size={17} />
              <div className={snapshot.tc.next ? "available" : "missing"}><span>2</span><strong>Next staged</strong><small>Ground promotion target</small></div>
              <ArrowRight size={17} />
              <div className={snapshot.tc.next ? "available" : "missing"}><span>3</span><strong>Flight convergence</strong><small>First valid next-SPI frame</small></div>
            </div>
            <p className="ops-panel-note">No on-wire switch command is exposed. The first accepted frame under the staged SPI completes flight-side convergence.</p>
          </Panel>
          <Panel title="Counter Budget">
            <div className="ops-budget-list">
              <div><Satellite size={15} /><span>Current ordinary frames remaining</span><strong>{remaining(snapshot.tc.current?.next_iv_counter)}</strong></div>
              <div><ShieldCheck size={15} /><span>Recovery frames remaining</span><strong>{remaining(snapshot.tc.recovery?.next_iv_counter)}</strong></div>
            </div>
            <p className="ops-panel-note">Rotation: <strong>{snapshot.tc_rotation?.phase ?? "NOT PREPARED"}</strong> · {snapshot.tc_rotation?.evidence ?? "NO GROUND EVIDENCE"}</p>
          </Panel>
        </div>

        <Panel title={`TC Action Queue / ${tcWarnings.length}`}><WarningList warnings={tcWarnings} /></Panel>
      </>}
    </PageContainer>
  );
}
