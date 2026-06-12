"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { api, Report } from "@/lib/api";
import { Card, Button, PageHeader } from "@/components/ui";

export default function ReportPreviewPage() {
  const params = useParams();
  const id = Number(params.id);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (id) {
      api
        .get<Report>(`/reports/${id}`)
        .then(setReport)
        .catch((e) => setError(e.message));
    }
  }, [id]);

  const exportMd = () => {
    if (!report) return;
    const blob = new Blob([report.content_markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `finding_${report.finding_id}_report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (error) return <p className="text-red-600">Failed to load report: {error}</p>;
  if (!report) return <p className="text-slate-400">Loading…</p>;

  return (
    <div>
      <PageHeader
        title="Report Preview"
        subtitle={report.title}
        action={
          <div className="flex gap-2">
            <Link
              href={`/findings/${report.finding_id}`}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50"
            >
              View finding
            </Link>
            <Button onClick={exportMd}>Export Markdown</Button>
          </div>
        }
      />

      <Card>
        <pre className="max-h-[75vh] overflow-auto whitespace-pre-wrap text-sm leading-relaxed text-slate-800">
          {report.content_markdown}
        </pre>
      </Card>

      {report.file_path && (
        <p className="mt-3 text-xs text-slate-400">Saved to: {report.file_path}</p>
      )}
    </div>
  );
}
