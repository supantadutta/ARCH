"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { api, Finding, Report, DuplicateCandidate } from "@/lib/api";
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
  const router = useRouter();
  const id = Number(params.id);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [dupes, setDupes] = useState<DuplicateCandidate[] | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => api.get<Finding>(`/findings/${id}`).then(setFinding);
  useEffect(() => {
    if (id) load();
  }, [id]);

  const triage = async () => {
    setBusy(true);
    setMsg("Running AI triage…");
    try {
      await api.post(`/findings/${id}/triage`);
      await load();
      setMsg("AI triage applied (evidence-grounded; nothing invented).");
    } catch (e: any) {
      setMsg(`Triage failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const setStatus = async (status: string) => {
    await api.patch(`/findings/${id}`, { status });
    load();
  };

  const genReport = async () => {
    setBusy(true);
    setMsg("Generating bug bounty report…");
    try {
      const r = await api.post<Report>(`/findings/${id}/report`);
      setReport(r);
      setMsg("Report generated.");
    } finally {
      setBusy(false);
    }
  };

  const findDuplicates = async () => {
    setMsg("Checking for duplicates…");
    const res = await api.get<{ candidates: DuplicateCandidate[] }>(`/findings/${id}/duplicates`);
    setDupes(res.candidates);
    setMsg(res.candidates.length ? `${res.candidates.length} candidate duplicate(s) found.` : "No duplicates found.");
  };

  const markDuplicate = async () => {
    await api.post(`/findings/${id}/deduplicate`);
    await load();
    setMsg("Linked to its earliest matching duplicate.");
  };

  if (!finding) return <p className="text-slate-400">Loading…</p>;

  return (
    <div>
      <PageHeader
        title={finding.title}
        subtitle={`Finding #${finding.id} · ${finding.scanner_name || "manual"}`}
        action={
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" onClick={triage} disabled={busy}>
              Run AI Triage
            </Button>
            <Button variant="secondary" onClick={findDuplicates} disabled={busy}>
              Find Duplicates
            </Button>
            <Button onClick={genReport} disabled={busy}>
              Generate Bug Bounty Report
            </Button>
          </div>
        }
      />

      {msg && <p className="mb-4 text-sm text-slate-500">{msg}</p>}

      {finding.duplicate_of && (
        <div className="mb-6 rounded-lg border border-slate-300 bg-slate-50 p-3 text-sm text-slate-700">
          🔁 Marked as a duplicate of{" "}
          <Link href={`/findings/${finding.duplicate_of}`} className="text-brand hover:underline">
            finding #{finding.duplicate_of}
          </Link>
          .
        </div>
      )}

      {dupes && dupes.length > 0 && (
        <Card className="mb-6">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="font-semibold">Candidate Duplicates</h3>
            <Button variant="secondary" onClick={markDuplicate}>
              Mark as duplicate of earliest
            </Button>
          </div>
          <ul className="space-y-1 text-sm">
            {dupes.map((d) => (
              <li key={d.finding_id} className="flex items-center justify-between">
                <Link href={`/findings/${d.finding_id}`} className="text-brand hover:underline">
                  #{d.finding_id} {d.title}
                </Link>
                <span className="text-slate-400">
                  score {d.score.toFixed(2)} · {d.reasons.join(", ")}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}

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
              <div className="mb-2 flex items-center justify-between">
                <h3 className="font-semibold">Bug Bounty Report</h3>
                <div className="flex gap-2">
                  <button
                    onClick={() => router.push(`/reports/${report.id}`)}
                    className="text-xs text-brand hover:underline"
                  >
                    open preview
                  </button>
                  <button
                    onClick={() => downloadMarkdown(report)}
                    className="text-xs text-brand hover:underline"
                  >
                    export .md
                  </button>
                </div>
              </div>
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

// Trigger a client-side download of the report's Markdown content.
function downloadMarkdown(report: Report) {
  const blob = new Blob([report.content_markdown], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `finding_${report.finding_id}_report.md`;
  a.click();
  URL.revokeObjectURL(url);
}
