"use client";

// Shared hook + selector for choosing the "active" program. The selection is
// persisted in localStorage so it is stable across page navigation.
import { useEffect, useState } from "react";
import { api, Program } from "@/lib/api";

const STORAGE_KEY = "abh.selectedProgram";

export function useProgram() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    api.get<Program[]>("/programs").then((p) => {
      setPrograms(p);
      const stored = Number(localStorage.getItem(STORAGE_KEY));
      if (stored && p.some((x) => x.id === stored)) {
        setSelected(stored);
      } else if (p.length > 0) {
        setSelected(p[0].id);
      }
    });
  }, []);

  const choose = (id: number) => {
    setSelected(id);
    localStorage.setItem(STORAGE_KEY, String(id));
  };

  return { programs, selected, choose };
}

export function ProgramSelector({
  programs,
  selected,
  onChange,
}: {
  programs: Program[];
  selected: number | null;
  onChange: (id: number) => void;
}) {
  if (programs.length === 0) {
    return <span className="text-sm text-slate-400">No programs yet — create one first.</span>;
  }
  return (
    <select
      value={selected ?? ""}
      onChange={(e) => onChange(Number(e.target.value))}
      className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm"
    >
      {programs.map((p) => (
        <option key={p.id} value={p.id}>
          {p.name}
        </option>
      ))}
    </select>
  );
}
