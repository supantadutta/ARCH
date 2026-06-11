"use client";

import { useEffect, useState } from "react";
import { api, ScopeItem } from "@/lib/api";
import { Card, Button, PageHeader } from "@/components/ui";
import { useProgram, ProgramSelector } from "@/components/useProgram";

const SCOPE_TYPES = ["domain", "wildcard_domain", "ip", "cidr", "repo", "mobile_app"];

export default function ScopePage() {
  const { programs, selected, choose } = useProgram();
  const [items, setItems] = useState<ScopeItem[]>([]);
  const [scopeType, setScopeType] = useState("domain");
  const [value, setValue] = useState("");
  const [isAllowed, setIsAllowed] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    if (selected) api.get<ScopeItem[]>(`/programs/${selected}/scope`).then(setItems);
  };
  useEffect(() => {
    load();
  }, [selected]);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.post(`/programs/${selected}/scope`, { scope_type: scopeType, value, is_allowed: isAllowed });
      setValue("");
      load();
    } catch (e: any) {
      setError(e.message);
    }
  };

  const remove = async (itemId: number) => {
    await api.del(`/programs/${selected}/scope/${itemId}`);
    load();
  };

  return (
    <div>
      <PageHeader
        title="Scope Management"
        subtitle="Only explicitly allowed targets can ever be scanned"
        action={<ProgramSelector programs={programs} selected={selected} onChange={choose} />}
      />

      <Card className="mb-6">
        <h3 className="mb-3 font-semibold">Add Scope Entry</h3>
        <form onSubmit={add} className="flex flex-wrap items-end gap-3">
          <div>
            <label className="block text-xs text-slate-500">Type</label>
            <select
              value={scopeType}
              onChange={(e) => setScopeType(e.target.value)}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
            >
              {SCOPE_TYPES.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-xs text-slate-500">Value</label>
            <input
              required
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="localhost or 127.0.0.1 or *.example.com"
              className="w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={isAllowed} onChange={(e) => setIsAllowed(e.target.checked)} />
            Allowed
          </label>
          <Button type="submit" disabled={!selected}>
            Add
          </Button>
        </form>
        {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
      </Card>

      <Card>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-slate-500">
              <th className="py-2">Type</th>
              <th>Value</th>
              <th>Decision</th>
              <th>Notes</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((s) => (
              <tr key={s.id} className="border-b last:border-0">
                <td className="py-2 font-mono">{s.scope_type}</td>
                <td className="font-mono">{s.value}</td>
                <td className={s.is_allowed ? "text-green-600" : "text-red-600"}>
                  {s.is_allowed ? "allowed" : "denied"}
                </td>
                <td className="text-slate-400">{s.notes}</td>
                <td className="text-right">
                  <button onClick={() => remove(s.id)} className="text-xs text-red-500 hover:underline">
                    remove
                  </button>
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={5} className="py-4 text-center text-slate-400">
                  No scope entries.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
