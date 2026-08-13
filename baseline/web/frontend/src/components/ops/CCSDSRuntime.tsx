import { AlertTriangle, CheckCircle2 } from "lucide-react";
import type { CCSDSAssociationStatus, CCSDSOperationsStatus } from "./queries";

const warningCopy: Record<string, string> = {
  TC_CURRENT_MISSING: "No TC Current association is available. Ordinary uplink protection is unavailable.",
  TC_NEXT_MISSING: "No TC Next association is staged. The next operational epoch is not ready.",
  TC_RECOVERY_MISSING: "No active Recovery GCM association is available.",
  TC_IV_NEAR_EXHAUSTION: "The TC Current IV counter is above 90%. Prepare the next epoch before exhaustion.",
  TC_CURRENT_AMBIGUOUS: "More than one TC Current association exists. Transmit state is ambiguous.",
  TC_NEXT_AMBIGUOUS: "More than one TC Next association exists. Staged state is ambiguous.",
  TC_RECOVERY_AMBIGUOUS: "More than one active Recovery association exists.",
  MISSION_PROFILE_NOT_BOUND: "No controlled Mission Security Profile digest is bound to this tenant.",
  FLIGHT_STATUS_NOT_OBSERVED: "No flight security status has been received through the housekeeping adapter.",
  FLIGHT_PROFILE_MISMATCH: "Flight and ground are using different Mission Security Profile digests.",
  FLIGHT_SELF_TEST_LOCKED: "Flight cryptography is locked because startup known-answer testing failed.",
  FLIGHT_TC_STATE_MISMATCH: "Flight Current SPI, epoch, root version, or Recovery SPI differs from ground.",
  FLIGHT_CYCLE_LIMIT_EXCEEDED: "Flight TC processing exceeded the 120 ms whole-cycle safety ceiling.",
  FLIGHT_CLOCK_ANOMALY: "The flight monotonic timing source moved backwards during TC processing.",
};

export const TC_COUNTER_CAPACITY = 2 ** 32;

export function formatSPI(spi?: number) {
  return spi === undefined ? "--" : `0x${spi.toString(16).toUpperCase().padStart(4, "0")}`;
}

export function formatCounter(value?: number) {
  return value === undefined ? "--" : value.toLocaleString("en-US");
}

export function formatObservedAt(value: string) {
  return new Date(value).toLocaleString("en-GB", { hour12: false });
}

export function statusTone(status: CCSDSOperationsStatus["status"]) {
  if (status === "READY") return "success";
  if (status === "DEGRADED") return "warning";
  return "neutral";
}

export function warningText(code: string) {
  return warningCopy[code] ?? code;
}

export function WarningList({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) {
    return <div className="ops-all-clear"><CheckCircle2 size={17} /><span>No active CCSDS operational alerts</span></div>;
  }
  return (
    <div className="ops-warning-list">
      {warnings.map((warning) => (
        <div key={warning}><AlertTriangle size={16} /><div><strong>{warning}</strong><span>{warningText(warning)}</span></div></div>
      ))}
    </div>
  );
}

export function AssociationCard({ title, association, counter = false }: {
  title: string;
  association: CCSDSAssociationStatus | null;
  counter?: boolean;
}) {
  if (!association) {
    return (
      <article className="association-card missing">
        <div className="association-card-title"><span>{title}</span><strong>UNAVAILABLE</strong></div>
        <div className="association-empty"><AlertTriangle size={18} />No usable security association</div>
      </article>
    );
  }
  const usage = counter && association.next_iv_counter !== undefined
    ? Math.min(100, association.next_iv_counter / TC_COUNTER_CAPACITY * 100)
    : 0;
  return (
    <article className="association-card">
      <div className="association-card-title"><span>{title}</span><strong>{association.state}</strong></div>
      <div className="association-spi">{formatSPI(association.spi)}</div>
      <dl className="association-details">
        <div><dt>Suite</dt><dd>{association.suite_id}</dd></div>
        <div><dt>Key version</dt><dd>v{association.key_version}</dd></div>
        <div><dt>Policy version</dt><dd>v{association.policy_version}</dd></div>
        {association.security_epoch > 0 && <div><dt>Security epoch</dt><dd>{association.security_epoch}</dd></div>}
      </dl>
      {counter && (
        <div className="counter-usage">
          <div><span>Next IV</span><strong>{formatCounter(association.next_iv_counter)}</strong></div>
          <div className="counter-track"><i style={{ width: `${usage}%` }} /></div>
          <small>{usage.toFixed(2)}% consumed</small>
        </div>
      )}
    </article>
  );
}
