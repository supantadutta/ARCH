"use client";

import { useEffect, useState } from "react";
import { api, Asset } from "@/lib/api";
import { Card, PageHeader } from "@/components/ui";
import { useProgram, ProgramSelector } from "@/components/useProgram";

export default function AssetsPage() {
  const { programs, selected, choose } = useProgram();
  const [assets, setAssets] = useState<Asset[]>([]);

  useEffect(() => {
    if (selected) api.get<Asset[]>(`/programs/${selected}/assets`).then(setAssets);
  }, [selected]);

  return (
    <div>
      <PageHeader
        title="Asset Inventory"
        subtitle="Discovered assets, ranked by risk score"
        action={<ProgramSelector programs={programs} selected={selected} onChange={choose} />}
      />
      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2">Asset</th>
              <th>Type</th>
              <th>IP</th>
              <th>Scheme</th>
              <th>Technologies</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => (
              <tr key={a.id} className="border-b last:border-0">
                <td className="py-2 font-mono">{a.value}</td>
                <td>{a.asset_type}</td>
                <td className="font-mono text-slate-500">{a.ip_address || "—"}</td>
                <td>{a.scheme || "—"}</td>
                <td className="text-slate-500">{a.technologies || "—"}</td>
                <td>{a.risk_score.toFixed(1)}</td>
              </tr>
            ))}
            {assets.length === 0 && (
              <tr>
                <td colSpan={6} className="py-4 text-center text-slate-400">
                  No assets. Run recon to discover assets.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
