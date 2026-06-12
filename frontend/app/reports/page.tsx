"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, Report } from "@/lib/api";
import { Card, PageHeader } from "@/components/ui";
import { useProgram, ProgramSelector } from "@/components/useProgram";

function exportMd(report: Report) {
  const blob = new Blob([report.content_markdown], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `finding_${report.finding_id}_report.md`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const { programs, selected, choose } = useProgram();
  const [reports, setReports] = useState<Report[]>([]);
  const [active, setActive] = useState<Report | null>(null);

  useEffect(() => {
    if (selected) api.get<Report[]>(`/programs/${selected}/reports`).then(setReports);
  }, [selected]);

  return (
    <div>
      <PageHeader
        title="Reports"
        subtitle="Markdown reports generated from confirmed findings"
        action={<ProgramSelector programs={programs} selected={selected} onChange={choose} />}
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <h3 className="mb-3 font-semibold">Generated Reports</h3>
          <ul className="space-y-2">
            {reports.map((r) => (
              <li key={r.id}>
                <button
                  onClick={() => setActive(r)}
                  className={`w-full rounded-lg px-3 py-2 text-left text-sm ${
                    active?.id === r.id ? "bg-brand text-white" : "hover:bg-slate-100"
                  }`}
                >
                  {r.title}
                </button>
              </li>
            ))}
            {reports.length === 0 && <li className="text-sm text-slate-400">No reports yet.</li>}
          </ul>
        </Card>

        <Card className="lg:col-span-2">
          {active ? (
            <>
              <div className="mb-2 flex items-center justify-between">
                <h3 className="font-semibold">{active.title}</h3>
                <div className="flex gap-3 text-xs">
                  <Link href={`/reports/${active.id}`} className="text-brand hover:underline">
                    open full preview
                  </Link>
                  <button onClick={() => exportMd(active)} className="text-brand hover:underline">
                    export .md
                  </button>
                </div>
              </div>
              <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap text-xs text-slate-700">
                {active.content_markdown}
              </pre>
            </>
          ) : (
            <p className="text-sm text-slate-400">Select a report to preview its Markdown.</p>
          )}
        </Card>
      </div>
    </div>
  );
}
