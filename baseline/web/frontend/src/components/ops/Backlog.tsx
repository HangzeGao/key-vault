import { useMutation, useQueryClient } from "@tanstack/react-query";
import { RotateCcw } from "lucide-react";
import { api } from "../../lib/api";
import { apiPaths, collectOpsAction } from "../../lib/apiPaths";
import { Panel, showToast } from "../index";
import { useFailedLifecycleJobs, usePendingOutboxEvents, type LifecycleJob, type OutboxEvent } from "./queries";

export function Backlog() {
  const jobsQ = useFailedLifecycleJobs();
  const outboxQ = usePendingOutboxEvents();
  const qc = useQueryClient();

  const retryMut = useMutation({
    mutationFn: (jobID: string) => { const action = collectOpsAction(`Retry lifecycle job ${jobID}`); if (!action) throw new Error("operation cancelled"); return api.post(apiPaths.ops.retryJob(jobID), action.body, action.headers); },
    onSuccess: () => {
      showToast("job retried", "success");
      qc.invalidateQueries({ queryKey: ["ops"] });
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const replayMut = useMutation({
    mutationFn: (eventID: string) => { const action = collectOpsAction(`Replay outbox event ${eventID}`); if (!action) throw new Error("operation cancelled"); return api.post(apiPaths.ops.replayOutbox(eventID), action.body, action.headers); },
    onSuccess: () => {
      showToast("event replayed", "success");
      qc.invalidateQueries({ queryKey: ["ops"] });
    },
    onError: (e: Error) => showToast(e.message, "error"),
  });

  const jobs: LifecycleJob[] = jobsQ.data?.jobs ?? [];
  const events: OutboxEvent[] = outboxQ.data?.events ?? [];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
      <Panel title="Lifecycle Backlog">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <span style={{ color: "var(--accent)", fontSize: 12, fontWeight: 700, letterSpacing: 0.5 }}>FAILED JOBS</span>
          <span className="mono" style={{ color: jobs.length > 0 ? "var(--warning)" : "var(--success)", fontSize: 10 }}>
            {jobs.length} failed
          </span>
        </div>
        {jobs.length === 0 ? (
          <div style={{ padding: 16, textAlign: "center", color: "var(--text-tertiary)", fontSize: 10 }}>no failed jobs</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {jobs.map((j) => (
              <div key={j.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: 8, background: "var(--bg-inset)", border: "1px solid var(--border)", borderRadius: 4 }}>
                <div>
                  <div className="mono" style={{ color: "var(--text-secondary)", fontSize: 10 }}>{j.id}</div>
                  <div style={{ color: "var(--text-tertiary)", fontSize: 9 }}>{j.type} · attempt {j.attempt}</div>
                </div>
                <button
                  style={{ background: "rgba(34,211,238,0.1)", border: "1px solid var(--border-accent)", color: "var(--accent)", padding: "4px 10px", borderRadius: 3, fontSize: 10, cursor: "pointer" }}
                  onClick={() => retryMut.mutate(j.id)}
                  disabled={retryMut.isPending}
                >
                  <RotateCcw size={10} /> retry
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Outbox Backlog">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <span style={{ color: "var(--accent)", fontSize: 12, fontWeight: 700, letterSpacing: 0.5 }}>PENDING EVENTS</span>
          <span className="mono" style={{ color: events.length > 0 ? "var(--warning)" : "var(--success)", fontSize: 10 }}>
            {events.length} pending
          </span>
        </div>
        {events.length === 0 ? (
          <div style={{ padding: 16, textAlign: "center", color: "var(--text-tertiary)", fontSize: 10 }}>no pending events</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {events.map((e) => (
              <div key={e.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: 8, background: "var(--bg-inset)", border: "1px solid var(--border)", borderRadius: 4 }}>
                <div>
                  <div className="mono" style={{ color: "var(--text-secondary)", fontSize: 10 }}>{e.id}</div>
                  <div style={{ color: "var(--text-tertiary)", fontSize: 9 }}>{e.event_type} · attempts {e.attempts}</div>
                </div>
                <button
                  style={{ background: "rgba(34,211,238,0.1)", border: "1px solid var(--border-accent)", color: "var(--accent)", padding: "4px 10px", borderRadius: 3, fontSize: 10, cursor: "pointer" }}
                  onClick={() => replayMut.mutate(e.id)}
                  disabled={replayMut.isPending}
                >
                  <RotateCcw size={10} /> replay
                </button>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
