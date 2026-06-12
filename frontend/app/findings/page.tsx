"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, auth, Finding } from "@/lib/api";
import { Card, Badge, Button, PageHeader } from "@/components/ui";
import { useProgram, ProgramSelector } from "@/components/useProgram";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

function slaState(f: Finding): { label: string; cls: string } {
  if (!f.sla_due_at) return { label: "—", cls: "text-slate-400" };
  const due = new Date(f.sla_due_at).getTime();
  const open = !["resolved", "closed", "false_positive"].includes(f.status);
  if (open && Date.now() > due) return { label: "breached", cls: "text-red-600 font-medium" };
  return { label: new Date(f.sla_due_at).toLocaleDateString(), cls: "text-slate-500" };
}

const PAGE_SIZE = 25;

export default function FindingsPage() {
  const { programs, selected, choose } = useProgram();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    if (selected) {
      const params = new URLSearchParams();
      if (severity) params.set("severity", severity);
      if (q) params.set("q", q);
      params.set("limit", String(PAGE_SIZE));
      params.set("offset", String(offset));
      api.page<Finding>(`/programs/${selected}/findings?${params}`).then((p) => {
        setFindings(p.items);
        setTotal(p.total);
      });
    }
  }, [selected, severity, q, offset]);

  // Reset to the first page whenever filters change.
  useEffect(() => setOffset(0), [severity, q, selected]);

  // Download the CSV export with the current auth credentials.
  const exportCsv = async () => {
    if (!selected) return;
    const url = `${API_BASE}/programs/${selected}/findings.csv`;
    const headers: Record<string, string> = auth.token()
      ? { Authorization: `Bearer ${auth.token()}` }
      : { "X-API-Key": process.env.NEXT_PUBLIC_API_KEY || "dev-local-key" };
    const res = await fetch(url, { headers });
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `program_${selected}_findings.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Triage and manage discovered findings"
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" onClick={exportCsv} disabled={!selected}>
              Export CSV
            </Button>
            <ProgramSelector programs={programs} selected={selected} onChange={choose} />
          </div>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
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
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search title/description…"
          className="ml-auto rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
        />
      </div>

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2">Title</th>
              <th>Severity</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>SLA</th>
              <th>Review</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => {
              const sla = slaState(f);
              return (
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
                  <td className={sla.cls}>{sla.label}</td>
                  <td>{f.manual_review_required ? "⚠️ required" : "—"}</td>
                </tr>
              );
            })}
            {findings.length === 0 && (
              <tr>
                <td colSpan={6} className="py-4 text-center text-slate-400">
                  No findings.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
          <span>
            {total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <div className="flex gap-2">
            <button
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              className="rounded border border-slate-300 px-2 py-1 disabled:opacity-40"
            >
              Prev
            </button>
            <button
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
              className="rounded border border-slate-300 px-2 py-1 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </Card>
    </div>
  );
}
