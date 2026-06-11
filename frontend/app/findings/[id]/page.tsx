"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api, Finding, Report } from "@/lib/api";
import { Card, Badge, Button, PageHeader } from "@/components/ui";

const STATUSES = [
  "new",
  "needs_review",
  "confirmed",
  "false_positive",
  "submitted",
  "resolved",
  "closed",
];

export default function FindingDetailPage() {
  const params = useParams();
  const id = Number(params.id);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => api.get<Finding>(`/findings/${id}`).then(setFinding);
  useEffect(() => {
    if (id) load();
  }, [id]);

  const triage = async () => {
    setMsg("Running AI triage…");
    await api.post(`/findings/${id}/triage`);
    await load();
    setMsg("AI triage applied.");
  };

  const setStatus = async (status: string) => {
    await api.patch(`/findings/${id}`, { status });
    load();
  };

  const genReport = async () => {
    setMsg("Generating report…");
    const r = await api.post<Report>(`/findings/${id}/report`);
    setReport(r);
    setMsg("Report generated.");
  };

  if (!finding) return <p className="text-slate-400">Loading…</p>;

  return (
    <div>
      <PageHeader
        title={finding.title}
        subtitle={`Finding #${finding.id} · ${finding.scanner_name || "manual"}`}
        action={
          <div className="flex gap-2">
            <Button variant="secondary" onClick={triage}>
              Run AI Triage
            </Button>
            <Button onClick={genReport}>Generate Report</Button>
          </div>
        }
      />

      {msg && <p className="mb-4 text-sm text-slate-500">{msg}</p>}

      {finding.manual_review_required && (
        <div className="mb-6 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-800">
          ⚠️ Manual review required — this finding has not been auto-confirmed.
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <h3 className="mb-2 font-semibold">Description</h3>
            <p className="text-sm text-slate-600">{finding.description || "—"}</p>
          </Card>

          <Card>
            <h3 className="mb-2 font-semibold">Evidence</h3>
            <p className="text-sm text-slate-600">{finding.evidence_summary || "(no evidence captured)"}</p>
          </Card>

          <Card>
            <h3 className="mb-2 font-semibold">AI Summary</h3>
            <p className="text-sm text-slate-600">{finding.ai_summary || "Run AI triage to generate a summary."}</p>
          </Card>

          <Card>
            <h3 className="mb-2 font-semibold">Impact</h3>
            <p className="text-sm text-slate-600">{finding.impact || "—"}</p>
          </Card>

          <Card>
            <h3 className="mb-2 font-semibold">Remediation</h3>
            <p className="text-sm text-slate-600">{finding.remediation || "—"}</p>
          </Card>

          <Card>
            <h3 className="mb-2 font-semibold">Raw Scanner Output</h3>
            <pre className="max-h-64 overflow-auto rounded-lg bg-slate-900 p-3 text-xs text-green-200">
              {finding.raw_output || "(none)"}
            </pre>
          </Card>

          {report && (
            <Card>
              <h3 className="mb-2 font-semibold">Report Draft</h3>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-50 p-4 text-xs text-slate-700">
                {report.content_markdown}
              </pre>
            </Card>
          )}
        </div>

        <div className="space-y-6">
          <Card>
            <h3 className="mb-3 font-semibold">Properties</h3>
            <dl className="space-y-2 text-sm">
              <Row label="Severity" value={<Badge kind="severity" value={finding.severity} />} />
              <Row label="Confidence" value={finding.confidence} />
              <Row label="Status" value={<Badge kind="status" value={finding.status} />} />
              <Row label="Category" value={finding.category || "—"} />
              <Row label="CWE" value={finding.cwe || "—"} />
              <Row label="OWASP" value={finding.owasp || "—"} />
              <Row label="Asset" value={finding.asset_id ? `#${finding.asset_id}` : "—"} />
            </dl>
          </Card>

          <Card>
            <h3 className="mb-3 font-semibold">Update Status</h3>
            <div className="flex flex-wrap gap-2">
              {STATUSES.map((s) => (
                <button
                  key={s}
                  onClick={() => setStatus(s)}
                  className={`rounded-lg px-2.5 py-1 text-xs ${
                    finding.status === s ? "bg-brand text-white" : "border border-slate-300 text-slate-600"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <dt className="text-slate-500">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
  );
}
