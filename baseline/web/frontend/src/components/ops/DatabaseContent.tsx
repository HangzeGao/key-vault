import { useMemo } from "react";
import { Database, HardDrive, KeyRound, Layers3, Workflow } from "lucide-react";
import { formatBytes, formatCount } from "./widgets";
import { Panel } from "../index";
import type { DBStatusResponse } from "./queries";

type StatusTone = "active" | "disabled" | "pending" | "destroyed" | "expired";
const STATUS_META: Record<StatusTone, { label: string; color: string }> = {
  active: { label: "Active", color: "var(--success)" },
  disabled: { label: "Disabled", color: "var(--warning)" },
  pending: { label: "Destroy pending", color: "var(--danger)" },
  destroyed: { label: "Destroyed", color: "var(--text-tertiary)" },
  expired: { label: "Expired", color: "var(--info)" },
};

export function DatabaseContent({ capacity, keyInventory, capacityAvailable = true, backendRole }: {
  capacity: DBStatusResponse["capacity"] | undefined;
  keyInventory: DBStatusResponse["key_inventory"] | undefined;
  capacityAvailable?: boolean;
  backendRole?: DBStatusResponse["runtime"]["role"];
}) {
  const statuses = useMemo(() => ({
    active: keyInventory?.by_status.ACTIVE ?? 0,
    disabled: keyInventory?.by_status.DISABLED ?? 0,
    pending: keyInventory?.by_status.DESTROY_PENDING ?? 0,
    destroyed: keyInventory?.by_status.DESTROYED ?? 0,
    expired: keyInventory?.by_status.EXPIRED ?? 0,
  }), [keyInventory]);
  const suites = useMemo(() => Object.entries(keyInventory?.by_suite ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 6), [keyInventory]);
  const purposes = useMemo(() => Object.entries(keyInventory?.by_purpose ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 6), [keyInventory]);
  const tables = useMemo(() => {
    const entries = [...(capacity?.tables ?? [])].sort((a, b) => (b.table_bytes + b.index_bytes) - (a.table_bytes + a.index_bytes));
    const max = entries[0] ? entries[0].table_bytes + entries[0].index_bytes : 0;
    return entries.map((table) => ({ ...table, totalBytes: table.table_bytes + table.index_bytes, ratio: max > 0 ? ((table.table_bytes + table.index_bytes) / max) * 100 : 0 }));
  }, [capacity]);
  const totalKeys = keyInventory?.total ?? 0;
  const tableRows = tables.reduce((sum, table) => sum + table.estimated_rows, 0);
  return (
    <Panel title="Data Atlas" action={<span className="database-content-scope">global aggregate · no record values</span>}>
      <div className="database-atlas-overview">
        <div className="database-atlas-stat"><KeyRound size={15} /><span>Key estate</span><strong>{formatCount(totalKeys)}</strong><small>keys observed</small></div>
        <div className="database-atlas-stat"><Layers3 size={15} /><span>Crypto suites</span><strong>{suites.length}</strong><small>configured workloads</small></div>
        <div className="database-atlas-stat"><HardDrive size={15} /><span>Database</span><strong>{capacityAvailable ? formatBytes(capacity?.database_bytes) : "-"}</strong><small>{formatCount(tableRows)} {backendRole === "memory" ? "reported" : "estimated"} rows</small></div>
      </div>
      <div className="database-content-grid">
        <section className="database-content-block database-content-status" aria-label="Key status distribution">
          <div className="database-content-heading"><KeyRound size={14} /><span>Key status distribution</span><strong>{formatCount(totalKeys)}</strong></div>
          {totalKeys > 0 ? <><div className="status-distribution" role="img" aria-label={`${totalKeys} keys distributed by status`}>{(Object.keys(STATUS_META) as StatusTone[]).map((tone) => statuses[tone] > 0 && <span key={tone} className="status-distribution-segment" style={{ width: `${(statuses[tone] / totalKeys) * 100}%`, background: STATUS_META[tone].color }} />)}</div><div className="status-distribution-legend">{(Object.keys(STATUS_META) as StatusTone[]).map((tone) => <span key={tone}><i style={{ background: STATUS_META[tone].color }} />{STATUS_META[tone].label} {statuses[tone]}</span>)}</div></> : <div className="database-content-empty">No key records.</div>}
        </section>
        <section className="database-content-block" aria-label="Key suites">
          <div className="database-content-heading"><Layers3 size={14} /><span>Key suites</span><strong>{suites.length}</strong></div>
          {suites.length > 0 ? <div className="database-rank-list">{suites.map(([suite, count]) => <div className="database-rank-row" key={suite}><span className="mono">{suite}</span><span className="database-rank-track"><i style={{ width: `${totalKeys > 0 ? (count / totalKeys) * 100 : 0}%` }} /></span><strong>{count}</strong></div>)}</div> : <div className="database-content-empty">No suite records.</div>}
        </section>
        <section className="database-content-block" aria-label="Key purposes">
          <div className="database-content-heading"><Workflow size={14} /><span>Key workloads</span><strong>{purposes.length}</strong></div>
          {purposes.length > 0 ? <div className="database-rank-list">{purposes.map(([purpose, count]) => <div className="database-rank-row" key={purpose}><span className="mono">{purpose.replaceAll("_", " ")}</span><span className="database-rank-track"><i style={{ width: `${totalKeys > 0 ? (count / totalKeys) * 100 : 0}%` }} /></span><strong>{count}</strong></div>)}</div> : <div className="database-content-empty">No workload records.</div>}
        </section>
        <section className="database-content-block database-content-tables" aria-label="Repository table capacity">
          <div className="database-content-heading"><Database size={14} /><span>Repository capacity</span><strong>{tables.length} tables</strong></div>
          {tables.length > 0 ? <div className="database-rank-list">{tables.map((table) => <div className="database-rank-row" key={table.name}><span className="mono database-table-name">{table.name}</span><span className="database-rank-track"><i style={{ width: `${table.ratio}%` }} /></span><strong>{formatCount(table.estimated_rows)} · {capacityAvailable ? formatBytes(table.totalBytes) : "size unavailable"}</strong></div>)}</div> : <div className="database-content-empty">Table statistics unavailable.</div>}
        </section>
      </div>
      <div className="database-content-note">{backendRole === "memory" ? "Memory row counts are exact for this process; persistent capacity is not applicable." : "Row counts are PostgreSQL estimates and may lag until ANALYZE; capacity includes table and index bytes."} Sensitive columns and record values are never returned.</div>
    </Panel>
  );
}
