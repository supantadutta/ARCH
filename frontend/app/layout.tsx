import "./globals.css";
import type { Metadata } from "next";
import { NavLink } from "@/components/ui";

export const metadata: Metadata = {
  title: "AutoBugHunter",
  description: "Authorized-only automated bug bounty & vulnerability management platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="flex min-h-screen">
          <aside className="w-60 shrink-0 border-r border-slate-200 bg-white p-4">
            <div className="mb-6 px-2">
              <div className="text-lg font-bold text-brand">AutoBugHunter</div>
              <div className="text-xs text-slate-400">authorized scanning only</div>
            </div>
            <nav className="space-y-1">
              <NavLink href="/" label="Dashboard" />
              <NavLink href="/programs" label="Programs" />
              <NavLink href="/scope" label="Scope" />
              <NavLink href="/assets" label="Assets" />
              <NavLink href="/scans" label="Scan Jobs" />
              <NavLink href="/findings" label="Findings" />
              <NavLink href="/reports" label="Reports" />
              <NavLink href="/audit" label="Audit Log" />
              <NavLink href="/settings" label="Settings" />
            </nav>
            <div className="mt-8 rounded-lg bg-amber-50 p-3 text-xs text-amber-800">
              Dry-run is the default. Scans run only against explicitly authorized scope.
            </div>
          </aside>
          <main className="flex-1 p-8">{children}</main>
        </div>
      </body>
    </html>
  );
}
