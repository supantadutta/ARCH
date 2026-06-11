"use client";

import { useEffect, useState } from "react";
import { api, AuditLog } from "@/lib/api";
import { Card, Badge, PageHeader } from "@/components/ui";

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [decision, setDecision] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const q = decision ? `?decision=${decision}` : "";
    api
      .get<AuditLog[]>(`/audit${q}`)
      .then(setLogs)
      .catch((e) => setError(e.message));
  }, [decision]);

  return (
    <div>
      <PageHeader
        title="Audit Log"
        subtitle="Immutable trail of all security-relevant actions"
      />

      <div className="mb-4 flex gap-2">
        {["", "allowed", "rejected", "info"].map((d) => (
          <button
            key={d || "all"}
            onClick={() => setDecision(d)}
            className={`rounded-full px-3 py-1 text-xs ${
              decision === d ? "bg-brand text-white" : "border border-slate-300 bg-white text-slate-600"
            }`}
          >
            {d || "all"}
          </button>
        ))}
      </div>

      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2">Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>Decision</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id} className="border-b last:border-0 hover:bg-slate-50">
                <td className="whitespace-nowrap py-2 text-slate-500">
                  {new Date(l.created_at).toLocaleString()}
                </td>
                <td className="font-mono">{l.actor}</td>
                <td className="font-mono text-slate-700">{l.action}</td>
                <td className="font-mono text-slate-500">{l.target || "—"}</td>
                <td>
                  <Badge kind="decision" value={l.decision} />
                </td>
                <td className="text-slate-500">{l.detail || "—"}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr>
                <td colSpan={6} className="py-4 text-center text-slate-400">
                  No audit entries.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
