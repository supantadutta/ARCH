"use client";

import { useEffect, useState } from "react";
import { api, Overview } from "@/lib/api";
import { Card, StatCard, Badge, PageHeader } from "@/components/ui";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_BAR: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-sky-500",
  info: "bg-slate-400",
};

// Simple horizontal bar chart (no external chart dependency).
function SeverityChart({ data }: { data: Record<string, number> }) {
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => data[s] ?? 0));
  return (
    <div className="space-y-2">
      {SEVERITY_ORDER.map((sev) => {
        const v = data[sev] ?? 0;
        return (
          <div key={sev} className="flex items-center gap-3 text-sm">
            <span className="w-16 capitalize text-slate-500">{sev}</span>
            <div className="h-4 flex-1 rounded bg-slate-100">
              <div
                className={`h-4 rounded ${SEVERITY_BAR[sev]}`}
                style={{ width: `${(v / max) * 100}%` }}
              />
            </div>
            <span className="w-8 text-right font-medium">{v}</span>
          </div>
        );
      })}
    </div>
  );
}

function StatusChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  if (entries.length === 0) return <p className="text-sm text-slate-400">No findings yet.</p>;
  return (
    <div className="space-y-2">
      {entries.map(([status, v]) => (
        <div key={status} className="flex items-center gap-3 text-sm">
          <span className="w-28 truncate text-slate-500">{status}</span>
          <div className="h-4 flex-1 rounded bg-slate-100">
            <div className="h-4 rounded bg-brand" style={{ width: `${(v / max) * 100}%` }} />
          </div>
          <span className="w-8 text-right font-medium">{v}</span>
        </div>
      ))}
    </div>
  );
}

export default function DashboardPage() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Overview>("/dashboard/overview")
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-600">Failed to load dashboard: {error}</p>;
  if (!data) return <p className="text-slate-400">Loading…</p>;

  return (
    <div>
      <PageHeader title="Dashboard" subtitle="Overview of programs, assets, scans and findings" />

      {data.kill_switch_enabled && (
        <div className="mb-6 rounded-lg border border-red-300 bg-red-50 p-4 text-sm font-medium text-red-800">
          🛑 Global kill switch is ENGAGED — all scanning is disabled.
        </div>
      )}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        <StatCard label="Total Programs" value={data.total_programs} />
        <StatCard label="Total Assets" value={data.total_assets} />
        <StatCard label="Running Scans" value={data.running_scans} accent="text-blue-600" />
        <StatCard label="Needs Review" value={data.needs_review_findings} accent="text-amber-600" />
        <StatCard label="SLA Breached" value={data.sla_breached_findings ?? 0} accent="text-red-600" />
      </div>

      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <h3 className="mb-4 font-semibold">Open Findings by Severity</h3>
          <SeverityChart data={data.open_findings_by_severity} />
        </Card>
        <Card>
          <h3 className="mb-4 font-semibold">Findings by Status</h3>
          <StatusChart data={data.findings_by_status || {}} />
        </Card>
      </div>

      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <h3 className="mb-3 font-semibold">Recent Scan Jobs</h3>
          {data.recent_scan_jobs.length === 0 && <p className="text-sm text-slate-400">No scans yet.</p>}
          <ul className="space-y-2">
            {data.recent_scan_jobs.map((j) => (
              <li key={j.id} className="flex items-center justify-between text-sm">
                <span className="font-mono text-slate-600">
                  #{j.id} {j.job_type} → {j.target}
                  {j.dry_run && <span className="ml-1 text-xs text-amber-600">(dry-run)</span>}
                </span>
                <Badge kind="status" value={j.status} />
              </li>
            ))}
          </ul>
        </Card>

        <Card>
          <h3 className="mb-3 font-semibold">Top Risky Assets</h3>
          {data.top_risky_assets.length === 0 && <p className="text-sm text-slate-400">No assets yet.</p>}
          <ul className="space-y-2">
            {data.top_risky_assets.map((a) => (
              <li key={a.id} className="flex items-center justify-between text-sm">
                <span className="font-mono text-slate-600">{a.value}</span>
                <span className="text-slate-500">risk {a.risk_score.toFixed(1)}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
