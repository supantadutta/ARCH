"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api, Program, ScopeItem, Asset, ScanJob, Finding } from "@/lib/api";
import { Card, Badge, PageHeader, Button } from "@/components/ui";

export default function ProgramDetailPage() {
  const params = useParams();
  const id = Number(params.id);
  const [program, setProgram] = useState<Program | null>(null);
  const [scope, setScope] = useState<ScopeItem[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    api.get<Program>(`/programs/${id}`).then(setProgram).catch((e) => setError(e.message));
    api.get<ScopeItem[]>(`/programs/${id}/scope`).then(setScope);
    api.list<Asset>(`/programs/${id}/assets`).then(setAssets);
    api.list<ScanJob>(`/programs/${id}/scans`).then(setScans);
    api.list<Finding>(`/programs/${id}/findings`).then(setFindings);
  };
  useEffect(() => {
    if (id) load();
  }, [id]);

  const runRecon = async () => {
    const target = scope.find((s) => s.is_allowed)?.value || "localhost";
    try {
      await api.post(`/programs/${id}/scans`, { job_type: "recon", target, dry_run: true });
      load();
    } catch (e: any) {
      setError(e.message);
    }
  };

  if (error) return <p className="text-red-600">{error}</p>;
  if (!program) return <p className="text-slate-400">Loading…</p>;

  return (
    <div>
      <PageHeader
        title={program.name}
        subtitle={program.description}
        action={<Button onClick={runRecon}>Run Recon (dry-run)</Button>}
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <h3 className="mb-3 font-semibold">Scope ({scope.length})</h3>
          <ul className="space-y-1 text-sm">
            {scope.map((s) => (
              <li key={s.id} className="flex items-center justify-between">
                <span className="font-mono">
                  {s.scope_type}: {s.value}
                </span>
                <span className={s.is_allowed ? "text-green-600" : "text-red-600"}>
                  {s.is_allowed ? "allowed" : "denied"}
                </span>
              </li>
            ))}
          </ul>
        </Card>

        <Card>
          <h3 className="mb-3 font-semibold">Assets ({assets.length})</h3>
          <ul className="space-y-1 text-sm">
            {assets.map((a) => (
              <li key={a.id} className="font-mono text-slate-600">
                {a.scheme ? `${a.scheme}://` : ""}
                {a.value}
                {a.technologies && <span className="ml-2 text-xs text-slate-400">[{a.technologies}]</span>}
              </li>
            ))}
            {assets.length === 0 && <li className="text-slate-400">No assets discovered yet.</li>}
          </ul>
        </Card>

        <Card>
          <h3 className="mb-3 font-semibold">Recent Scans ({scans.length})</h3>
          <ul className="space-y-1 text-sm">
            {scans.slice(0, 8).map((j) => (
              <li key={j.id} className="flex items-center justify-between">
                <span className="font-mono">
                  #{j.id} {j.job_type}
                </span>
                <Badge kind="status" value={j.status} />
              </li>
            ))}
          </ul>
        </Card>

        <Card>
          <h3 className="mb-3 font-semibold">Findings ({findings.length})</h3>
          <ul className="space-y-1 text-sm">
            {findings.slice(0, 8).map((f) => (
              <li key={f.id} className="flex items-center justify-between">
                <span className="truncate">{f.title}</span>
                <Badge kind="severity" value={f.severity} />
              </li>
            ))}
            {findings.length === 0 && <li className="text-slate-400">No findings yet.</li>}
          </ul>
        </Card>
      </div>
    </div>
  );
}
