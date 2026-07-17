import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, RotateCcw, Send } from "lucide-react";
import { api } from "../../lib/api";
import { apiPaths, collectOpsAction } from "../../lib/apiPaths";
import { Panel, showToast } from "../index";

export function Actions() {
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);

  const refreshMut = useMutation({
    mutationFn: () => { const action = collectOpsAction("Refresh resolver from latest CRK envelope"); if (!action) throw new Error("operation cancelled"); return api.post(apiPaths.ops.resolverRefresh, action.body, action.headers); },
    onSuccess: () => {
      showToast("resolver refreshed", "success");
      qc.invalidateQueries({ queryKey: ["ops"] });
    },
    onError: (e: Error) => showToast(e.message, "error"),
    onSettled: () => setBusy(null),
  });

  const retryAllMut = useMutation({
    mutationFn: async () => {
      // Fetch failed jobs then retry each.
      const r = await api.get<{ jobs: { id: string }[] }>(apiPaths.lifecycle.jobs({ status: "FAILED", limit: 100 }));
      for (const j of r.jobs ?? []) {
        const action = collectOpsAction(`Retry failed lifecycle job ${j.id}`); if (!action) break;
        await api.post(apiPaths.ops.retryJob(j.id), action.body, action.headers);
      }
    },
    onSuccess: () => {
      showToast("all failed jobs retried", "success");
      qc.invalidateQueries({ queryKey: ["ops"] });
    },
    onError: (e: Error) => showToast(e.message, "error"),
    onSettled: () => setBusy(null),
  });

  const replayAllMut = useMutation({
    mutationFn: async () => {
      const r = await api.get<{ events: { id: string }[] }>(apiPaths.lifecycle.outbox({ status: "PENDING", limit: 100 }));
      for (const e of r.events ?? []) {
        const action = collectOpsAction(`Replay pending outbox event ${e.id}`); if (!action) break;
        await api.post(apiPaths.ops.replayOutbox(e.id), action.body, action.headers);
      }
    },
    onSuccess: () => {
      showToast("all pending outbox replayed", "success");
      qc.invalidateQueries({ queryKey: ["ops"] });
    },
    onError: (e: Error) => showToast(e.message, "error"),
    onSettled: () => setBusy(null),
  });

  const btn = (key: string, mut: { mutate: () => void; isPending: boolean }, icon: React.ReactNode, label: string) => (
    <button
      className="btn btn-secondary"
      onClick={() => { setBusy(key); mut.mutate(); }}
      disabled={busy !== null}
      style={{ background: "rgba(34,211,238,0.1)", border: "1px solid var(--border-accent)", color: "var(--accent)" }}
    >
      {icon} {mut.isPending ? "..." : label}
    </button>
  );

  return (
    <Panel title="Controlled Actions">
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {btn("refresh", refreshMut, <RefreshCw size={14} />, "Resolver Refresh")}
        {btn("retryAll", retryAllMut, <RotateCcw size={14} />, "Retry All Failed Jobs")}
        {btn("replayAll", replayAllMut, <Send size={14} />, "Replay All Pending Outbox")}
      </div>
    </Panel>
  );
}
