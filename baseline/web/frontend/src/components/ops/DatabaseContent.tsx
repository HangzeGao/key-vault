import { useMemo } from "react";
import { Database, KeyRound, Layers3, Workflow } from "lucide-react";
import type { KeyDTO } from "../../lib/types";
import { formatCount } from "./widgets";
import { Panel } from "../index";
import type { DBStatusResponse } from "./queries";

type StatusTone = "active" | "disabled" | "pending" | "destroyed" | "expired";
const STATUS_META: Record<StatusTone, { label: string; color: string }> = {
  active: { label: "Active", color: "var(--success)" }, disabled: { label: "Disabled", color: "var(--warning)" },
  pending: { label: "Destroy pending", color: "var(--danger)" }, destroyed: { label: "Destroyed", color: "var(--text-tertiary)" }, expired: { label: "Expired", color: "var(--info)" },
};

function statusTone(status: KeyDTO["status"]): StatusTone {
  switch (status) { case "ACTIVE": return "active"; case "DISABLED": return "disabled"; case "DESTROY_PENDING": return "pending"; case "DESTROYED": return "destroyed"; case "EXPIRED": return "expired"; default: return "disabled"; }
}

export function DatabaseContent({ keys, tableSizes, keyInventory }: { keys: KeyDTO[]; tableSizes?: Record<string, number>; keyInventory?: DBStatusResponse["key_inventory"] }) {
  const statuses = useMemo(() => { const counts: Record<StatusTone, number> = { active: 0, disabled: 0, pending: 0, destroyed: 0, expired: 0 }; keys.forEach((key) => { counts[statusTone(key.status)] += 1; }); return counts; }, [keys]);
  const suites = useMemo(() => { const counts = new Map<string, number>(); keys.forEach((key) => counts.set(key.suite_id, (counts.get(key.suite_id) ?? 0) + 1)); return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4); }, [keys]);
  const purposes = useMemo(() => { const counts = new Map<string, number>(); keys.forEach((key) => counts.set(key.purpose, (counts.get(key.purpose) ?? 0) + 1)); return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4); }, [keys]);
  const tables = useMemo(() => { const entries = Object.entries(tableSizes ?? {}).sort((a, b) => b[1] - a[1]); const max = entries[0]?.[1] ?? 0; return entries.map(([name, count]) => ({ name, count, ratio: max > 0 ? (count / max) * 100 : 0 })); }, [tableSizes]);
  const aggregateStatus = useMemo(() => ({ active: keyInventory?.by_status.ACTIVE ?? 0, disabled: keyInventory?.by_status.DISABLED ?? 0, pending: keyInventory?.by_status.DESTROY_PENDING ?? 0, destroyed: keyInventory?.by_status.DESTROYED ?? 0, expired: keyInventory?.by_status.EXPIRED ?? 0 }), [keyInventory]);
  const aggregateSuites = useMemo(() => Object.entries(keyInventory?.by_suite ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 4), [keyInventory]);
  const aggregatePurposes = useMemo(() => Object.entries(keyInventory?.by_purpose ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 4), [keyInventory]);
  const usingAggregate = keys.length === 0 && Boolean(keyInventory);
  const displayStatuses = usingAggregate ? aggregateStatus : statuses;
  const displaySuites = usingAggregate ? aggregateSuites : suites;
  const displayPurposes = usingAggregate ? aggregatePurposes : purposes;
  const totalKeys = usingAggregate ? (keyInventory?.total ?? 0) : keys.length;
  const scopeLabel = usingAggregate ? "global aggregate" : "visible tenant records";
  return (
    <Panel title="Data Atlas" action={<span className="database-content-scope">{scopeLabel}</span>}>
      <div className="database-atlas-overview">
        <div className="database-atlas-stat"><KeyRound size={15} /><span>Key estate</span><strong>{formatCount(totalKeys)}</strong><small>keys observed</small></div>
        <div className="database-atlas-stat"><Layers3 size={15} /><span>Crypto suites</span><strong>{displaySuites.length}</strong><small>in active inventory</small></div>
        <div className="database-atlas-stat"><Database size={15} /><span>Repository</span><strong>{formatCount(tables.reduce((sum, table) => sum + table.count, 0))}</strong><small>rows across {tables.length} tables</small></div>
      </div>
      <div className="database-content-grid">
        <section className="database-content-block database-content-status" aria-label="Key status distribution">
          <div className="database-content-heading"><KeyRound size={14} /><span>Key status distribution</span><strong>{formatCount(totalKeys)}</strong></div>
          {totalKeys > 0 ? <><div className="status-distribution" role="img" aria-label={`${totalKeys} keys distributed by status`}>{(Object.keys(STATUS_META) as StatusTone[]).map((tone) => displayStatuses[tone] > 0 && <span key={tone} className="status-distribution-segment" style={{ width: `${(displayStatuses[tone] / totalKeys) * 100}%`, background: STATUS_META[tone].color }} />)}</div><div className="status-distribution-legend">{(Object.keys(STATUS_META) as StatusTone[]).map((tone) => <span key={tone}><i style={{ background: STATUS_META[tone].color }} />{STATUS_META[tone].label} {displayStatuses[tone]}</span>)}</div></> : <div className="database-content-empty">No key records.</div>}
        </section>
        <section className="database-content-block" aria-label="Key suites">
          <div className="database-content-heading"><Layers3 size={14} /><span>Key suites</span><strong>{displaySuites.length}</strong></div>
          {displaySuites.length > 0 ? <div className="database-rank-list">{displaySuites.map(([suite, count]) => <div className="database-rank-row" key={suite}><span className="mono">{suite}</span><span className="database-rank-track"><i style={{ width: `${totalKeys > 0 ? (count / totalKeys) * 100 : 0}%` }} /></span><strong>{count}</strong></div>)}</div> : <div className="database-content-empty">No suite records.</div>}
        </section>
        <section className="database-content-block" aria-label="Key purposes">
          <div className="database-content-heading"><Workflow size={14} /><span>Key workloads</span><strong>{displayPurposes.length}</strong></div>
          {displayPurposes.length > 0 ? <div className="database-rank-list">{displayPurposes.map(([purpose, count]) => <div className="database-rank-row" key={purpose}><span className="mono">{purpose.replaceAll("_", " ")}</span><span className="database-rank-track"><i style={{ width: `${totalKeys > 0 ? (count / totalKeys) * 100 : 0}%` }} /></span><strong>{count}</strong></div>)}</div> : <div className="database-content-empty">No workload records.</div>}
        </section>
        <section className="database-content-block database-content-tables" aria-label="Repository table sizes">
          <div className="database-content-heading"><Database size={14} /><span>Repository footprint</span><strong>{tables.length} tables</strong></div>
          {tables.length > 0 ? <div className="database-rank-list">{tables.map((table) => <div className="database-rank-row" key={table.name}><span className="mono database-table-name">{table.name}</span><span className="database-rank-track"><i style={{ width: `${table.ratio}%` }} /></span><strong>{formatCount(table.count)}</strong></div>)}</div> : <div className="database-content-empty">Table statistics unavailable.</div>}
        </section>
      </div>
      <div className="database-content-note">Key charts use {scopeLabel}; repository row counts are global operational diagnostics.</div>
    </Panel>
  );
}
