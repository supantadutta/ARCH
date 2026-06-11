// Small reusable presentational components shared across pages.
import Link from "next/link";
import { ReactNode } from "react";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-slate-200 bg-white p-5 shadow-sm ${className}`}>
      {children}
    </div>
  );
}

export function StatCard({ label, value, accent = "text-slate-900" }: { label: string; value: ReactNode; accent?: string }) {
  return (
    <Card>
      <div className="text-sm font-medium text-slate-500">{label}</div>
      <div className={`mt-2 text-3xl font-semibold ${accent}`}>{value}</div>
    </Card>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-100 text-red-800 border-red-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  medium: "bg-amber-100 text-amber-800 border-amber-200",
  low: "bg-sky-100 text-sky-800 border-sky-200",
  info: "bg-slate-100 text-slate-700 border-slate-200",
};

const STATUS_COLORS: Record<string, string> = {
  new: "bg-slate-100 text-slate-700",
  needs_review: "bg-amber-100 text-amber-800",
  confirmed: "bg-green-100 text-green-800",
  false_positive: "bg-slate-100 text-slate-500",
  resolved: "bg-emerald-100 text-emerald-800",
  running: "bg-blue-100 text-blue-800",
  queued: "bg-indigo-100 text-indigo-800",
  completed: "bg-green-100 text-green-800",
  failed: "bg-red-100 text-red-800",
  cancelled: "bg-slate-100 text-slate-500",
};

const DECISION_COLORS: Record<string, string> = {
  allowed: "bg-green-100 text-green-800 border-green-200",
  rejected: "bg-red-100 text-red-800 border-red-200",
  info: "bg-slate-100 text-slate-700 border-slate-200",
};

export function Badge({ kind, value }: { kind: "severity" | "status" | "decision"; value: string }) {
  const map =
    kind === "severity" ? SEVERITY_COLORS : kind === "decision" ? DECISION_COLORS : STATUS_COLORS;
  const cls = map[value] || "bg-slate-100 text-slate-700";
  return (
    <span className={`inline-block rounded-full border px-2.5 py-0.5 text-xs font-medium ${cls}`}>
      {value}
    </span>
  );
}

export function Button({
  children,
  onClick,
  variant = "primary",
  type = "button",
  disabled,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "danger";
  type?: "button" | "submit";
  disabled?: boolean;
}) {
  const styles = {
    primary: "bg-brand text-white hover:bg-brand-dark",
    secondary: "bg-white text-slate-700 border border-slate-300 hover:bg-slate-50",
    danger: "bg-red-600 text-white hover:bg-red-700",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:opacity-50 ${styles[variant]}`}
    >
      {children}
    </button>
  );
}

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex items-end justify-between">
      <div>
        <h1 className="text-2xl font-semibold text-slate-900">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-500">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function NavLink({ href, label }: { href: string; label: string }) {
  return (
    <Link href={href} className="block rounded-lg px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100 hover:text-slate-900">
      {label}
    </Link>
  );
}
