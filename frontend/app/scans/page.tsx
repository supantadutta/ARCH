"use client";

import { useEffect, useState } from "react";
import { api, ScanJob } from "@/lib/api";
import { Card, Button, Badge, PageHeader } from "@/components/ui";
import { useProgram, ProgramSelector } from "@/components/useProgram";

const JOB_TYPES = ["recon", "nuclei", "zap_baseline", "semgrep", "gitleaks", "trivy"];

export default function ScansPage() {
  const { programs, selected, choose } = useProgram();
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [jobType, setJobType] = useState("recon");
  const [target, setTarget] = useState("localhost");
  const [dryRun, setDryRun] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedJob, setSelectedJob] = useState<ScanJob | null>(null);
  const [logTab, setLogTab] = useState<"logs" | "stdout" | "stderr">("logs");

  const load = () => {
    if (selected) api.get<ScanJob[]>(`/programs/${selected}/scans`).then(setJobs);
  };

  // Fetch the freshest copy of a job (logs/stdout/stderr/exit code) on open.
  const openLogs = async (job: ScanJob) => {
    setLogTab("logs");
    try {
      const fresh = await api.get<ScanJob>(`/programs/${selected}/scans/${job.id}`);
      setSelectedJob(fresh);
    } catch {
      setSelectedJob(job);
    }
  };
  useEffect(() => {
    load();
  }, [selected]);

  const launch = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.post(`/programs/${selected}/scans`, { job_type: jobType, target, dry_run: dryRun });
      load();
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div>
      <PageHeader
        title="Scan Jobs"
        subtitle="Launch scope-validated scans. Dry-run is on by default."
        action={<ProgramSelector programs={programs} selected={selected} onChange={choose} />}
      />

      <Card className="mb-6">
        <h3 className="mb-3 font-semibold">Launch Scan</h3>
        <form onSubmit={launch} className="flex flex-wrap items-end gap-3">
          <div>
            <label className="block text-xs text-slate-500">Type</label>
            <select
              value={jobType}
              onChange={(e) => setJobType(e.target.value)}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
            >
              {JOB_TYPES.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-xs text-slate-500">Target (must be in scope)</label>
            <input
              required
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
            Dry-run
          </label>
          <Button type="submit" disabled={!selected}>
            Launch
          </Button>
        </form>
        {error && <p className="mt-2 text-sm text-red-600">⛔ {error}</p>}
      </Card>

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2">#</th>
              <th>Type</th>
              <th>Target</th>
              <th>Dry-run</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((j) => (
              <tr key={j.id} className="border-b last:border-0">
                <td className="py-2">{j.id}</td>
                <td className="font-mono">{j.job_type}</td>
                <td className="font-mono text-slate-500">{j.target}</td>
                <td>{j.dry_run ? "yes" : "no"}</td>
                <td>
                  <Badge kind="status" value={j.status} />
                </td>
                <td className="text-right">
                  <button onClick={() => openLogs(j)} className="text-xs text-brand hover:underline">
                    logs
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <button onClick={load} className="mt-3 text-xs text-slate-400 hover:underline">
          ↻ refresh
        </button>
      </Card>

      {selectedJob && (
        <Card className="mt-6">
          <div className="mb-2 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h3 className="font-semibold">Job #{selectedJob.id} output</h3>
              <Badge kind="status" value={selectedJob.status} />
              <span className="text-xs text-slate-500">
                exit code: {selectedJob.exit_code ?? "—"}
              </span>
            </div>
            <button onClick={() => setSelectedJob(null)} className="text-xs text-slate-400">
              close
            </button>
          </div>
          {selectedJob.error_message && (
            <p className="mb-2 text-sm text-red-600">⛔ {selectedJob.error_message}</p>
          )}
          <div className="mb-2 flex gap-2">
            {(["logs", "stdout", "stderr"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setLogTab(t)}
                className={`rounded-lg px-3 py-1 text-xs ${
                  logTab === t ? "bg-brand text-white" : "border border-slate-300 text-slate-600"
                }`}
              >
                {t}
              </button>
            ))}
          </div>
          <pre className="max-h-80 overflow-auto rounded-lg bg-slate-900 p-4 text-xs text-green-200">
            {logTab === "logs"
              ? selectedJob.logs || "(no logs)"
              : logTab === "stdout"
                ? selectedJob.stdout || "(no stdout)"
                : selectedJob.stderr || "(no stderr)"}
          </pre>
        </Card>
      )}
    </div>
  );
}
