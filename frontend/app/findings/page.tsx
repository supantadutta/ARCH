"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, Finding } from "@/lib/api";
import { Card, Badge, PageHeader } from "@/components/ui";
import { useProgram, ProgramSelector } from "@/components/useProgram";

export default function FindingsPage() {
  const { programs, selected, choose } = useProgram();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState("");

  useEffect(() => {
    if (selected) {
      const q = severity ? `?severity=${severity}` : "";
      api.get<Finding[]>(`/programs/${selected}/findings${q}`).then(setFindings);
    }
  }, [selected, severity]);

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Triage and manage discovered findings"
        action={<ProgramSelector programs={programs} selected={selected} onChange={choose} />}
      />

      <div className="mb-4 flex gap-2">
        {["", "critical", "high", "medium", "low", "info"].map((s) => (
          <button
            key={s || "all"}
            onClick={() => setSeverity(s)}
            className={`rounded-full px-3 py-1 text-xs ${
              severity === s ? "bg-brand text-white" : "bg-white border border-slate-300 text-slate-600"
            }`}
          >
            {s || "all"}
          </button>
        ))}
      </div>

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2">Title</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Review</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id} className="border-b last:border-0 hover:bg-slate-50">
                <td className="py-2">
                  <Link href={`/findings/${f.id}`} className="text-brand hover:underline">
                    {f.title}
                  </Link>
                </td>
                <td>
                  <Badge kind="severity" value={f.severity} />
                </td>
                <td>{f.confidence}</td>
                <td>
                  <Badge kind="status" value={f.status} />
                </td>
                <td>{f.manual_review_required ? "⚠️ required" : "—"}</td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr>
                <td colSpan={5} className="py-4 text-center text-slate-400">
                  No findings.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
