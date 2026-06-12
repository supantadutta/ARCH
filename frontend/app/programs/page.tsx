"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, Program } from "@/lib/api";
import { Card, Button, Badge, PageHeader } from "@/components/ui";

export default function ProgramsPage() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = () => api.list<Program>("/programs").then(setPrograms).catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.post<Program>("/programs", { name, description });
      setName("");
      setDescription("");
      load();
    } catch (e: any) {
      setError(e.message);
    }
  };

  return (
    <div>
      <PageHeader title="Programs" subtitle="Bug bounty & vulnerability management programs" />

      <Card className="mb-6">
        <h3 className="mb-3 font-semibold">Create Program</h3>
        <form onSubmit={create} className="flex flex-wrap items-end gap-3">
          <div>
            <label className="block text-xs text-slate-500">Name</label>
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
              placeholder="Localhost Demo Program"
            />
          </div>
          <div className="flex-1">
            <label className="block text-xs text-slate-500">Description</label>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
              placeholder="Authorized scope only"
            />
          </div>
          <Button type="submit">Create</Button>
        </form>
        {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
      </Card>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {programs.map((p) => (
          <Link key={p.id} href={`/programs/${p.id}`}>
            <Card className="transition hover:shadow-md">
              <div className="flex items-center justify-between">
                <h3 className="font-semibold">{p.name}</h3>
                <Badge kind="status" value={p.status} />
              </div>
              <p className="mt-1 text-sm text-slate-500">{p.description || "No description"}</p>
              <p className="mt-3 text-xs text-slate-400">Created {new Date(p.created_at).toLocaleDateString()}</p>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
