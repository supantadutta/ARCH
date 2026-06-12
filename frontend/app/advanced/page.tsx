"use client";

import { useEffect, useState } from "react";
import {
  api,
  TestAccount,
  ApiEndpoint,
  PermissionRule,
  Checklist,
  SourceRoute,
} from "@/lib/api";
import { Card, Button, Badge, PageHeader } from "@/components/ui";
import { useProgram, ProgramSelector } from "@/components/useProgram";

const WORKFLOW_KINDS = [
  "signup", "login", "password_reset", "checkout", "coupon", "wallet",
  "team_invite", "role_change", "file_upload", "subscription", "refund",
  "api_key_generation",
];

export default function AdvancedPage() {
  const { programs, selected, choose } = useProgram();
  const [accounts, setAccounts] = useState<TestAccount[]>([]);
  const [endpoints, setEndpoints] = useState<ApiEndpoint[]>([]);
  const [rules, setRules] = useState<PermissionRule[]>([]);
  const [checklists, setChecklists] = useState<Checklist[]>([]);
  const [routes, setRoutes] = useState<SourceRoute[]>([]);
  const [msg, setMsg] = useState<string | null>(null);

  const p = selected;
  const load = () => {
    if (!p) return;
    api.get<TestAccount[]>(`/programs/${p}/test-accounts`).then(setAccounts).catch(() => {});
    api.get<ApiEndpoint[]>(`/programs/${p}/api/endpoints`).then(setEndpoints).catch(() => {});
    api.get<PermissionRule[]>(`/programs/${p}/permission-rules`).then(setRules).catch(() => {});
    api.get<Checklist[]>(`/programs/${p}/checklists`).then(setChecklists).catch(() => {});
    api.get<SourceRoute[]>(`/programs/${p}/source-routes`).then(setRoutes).catch(() => {});
  };
  useEffect(load, [p]);

  const run = async (fn: () => Promise<any>, label: string) => {
    setMsg(`${label}…`);
    try {
      const r = await fn();
      setMsg(`${label}: ${typeof r === "object" ? JSON.stringify(r).slice(0, 300) : r}`);
      load();
    } catch (e: any) {
      setMsg(`${label} failed: ${e.message}`);
    }
  };

  // --- form state ---
  const [acct, setAcct] = useState({ label: "", role: "user", login_url: "", secret: "", is_authorized: false });
  const [spec, setSpec] = useState("");
  const [rule, setRule] = useState({ role: "user", resource: "", action: "GET", expected_access: "deny" });
  const [wfKind, setWfKind] = useState("checkout");
  const [repoPath, setRepoPath] = useState("");
  const [acTargets, setAcTargets] = useState("");
  const [acA, setAcA] = useState<number | "">("");
  const [acB, setAcB] = useState<number | "">("");

  return (
    <div>
      <PageHeader
        title="Advanced Modules"
        subtitle="Authorized-only: authenticated crawl, API security, access control, permissions, business logic, workflows, payments, source routes"
        action={<ProgramSelector programs={programs} selected={selected} onChange={choose} />}
      />

      <div className="mb-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-800">
        Every module is authorized-only. Request-sending modules default to dry-run, stay in scope,
        use only authorized test accounts, never bulk-download, and flag risky results as
        <b> needs_review</b> for manual approval.
      </div>

      {msg && <p className="mb-4 break-words text-sm text-slate-600">{msg}</p>}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Test accounts */}
        <Card>
          <h3 className="mb-3 font-semibold">Authorized Test Accounts</h3>
          <ul className="mb-3 space-y-1 text-sm">
            {accounts.map((a) => (
              <li key={a.id} className="flex items-center justify-between">
                <span>
                  <span className="font-mono">{a.label}</span>{" "}
                  <span className="text-slate-400">({a.role})</span>
                </span>
                <span className={a.is_authorized ? "text-green-600 text-xs" : "text-red-600 text-xs"}>
                  {a.is_authorized ? "authorized" : "not authorized"}
                </span>
              </li>
            ))}
            {accounts.length === 0 && <li className="text-slate-400">No test accounts.</li>}
          </ul>
          <div className="space-y-2">
            <input className="w-full rounded border border-slate-300 px-2 py-1 text-sm" placeholder="Label"
              value={acct.label} onChange={(e) => setAcct({ ...acct, label: e.target.value })} />
            <div className="flex gap-2">
              <input className="w-1/2 rounded border border-slate-300 px-2 py-1 text-sm" placeholder="Role (guest/user/manager/admin)"
                value={acct.role} onChange={(e) => setAcct({ ...acct, role: e.target.value })} />
              <input className="w-1/2 rounded border border-slate-300 px-2 py-1 text-sm" placeholder="Login URL (optional)"
                value={acct.login_url} onChange={(e) => setAcct({ ...acct, login_url: e.target.value })} />
            </div>
            <input className="w-full rounded border border-slate-300 px-2 py-1 text-sm font-mono"
              placeholder='Secret JSON, e.g. {"username":"x","password":"y"} (stored encrypted)'
              value={acct.secret} onChange={(e) => setAcct({ ...acct, secret: e.target.value })} />
            <label className="flex items-center gap-2 text-xs">
              <input type="checkbox" checked={acct.is_authorized}
                onChange={(e) => setAcct({ ...acct, is_authorized: e.target.checked })} />
              I confirm this is an authorized test account
            </label>
            <Button onClick={() => run(() => api.post(`/programs/${p}/test-accounts`, acct), "Create account")} disabled={!p}>
              Add Test Account
            </Button>
          </div>
        </Card>

        {/* API security */}
        <Card>
          <h3 className="mb-3 font-semibold">API Security — Import & Inventory</h3>
          <textarea className="mb-2 h-24 w-full rounded border border-slate-300 px-2 py-1 font-mono text-xs"
            placeholder="Paste OpenAPI / Swagger / Postman JSON…"
            value={spec} onChange={(e) => setSpec(e.target.value)} />
          <Button onClick={() => run(() => api.post(`/programs/${p}/api/import`, { content: spec }), "Import API")} disabled={!p}>
            Import Collection
          </Button>
          <div className="mt-3 max-h-40 overflow-auto text-xs">
            {endpoints.map((e) => (
              <div key={e.id} className="flex items-center justify-between border-b py-1">
                <span className="font-mono">{e.method} {e.path}</span>
                {e.object_id_params && <span className="text-amber-600">ids: {e.object_id_params}</span>}
              </div>
            ))}
            {endpoints.length === 0 && <p className="text-slate-400">No endpoints imported.</p>}
          </div>
        </Card>

        {/* Permission matrix */}
        <Card>
          <h3 className="mb-3 font-semibold">Permission Matrix</h3>
          <div className="mb-2 flex flex-wrap gap-2">
            <input className="w-24 rounded border border-slate-300 px-2 py-1 text-sm" placeholder="role"
              value={rule.role} onChange={(e) => setRule({ ...rule, role: e.target.value })} />
            <input className="flex-1 rounded border border-slate-300 px-2 py-1 text-sm" placeholder="resource (/path)"
              value={rule.resource} onChange={(e) => setRule({ ...rule, resource: e.target.value })} />
            <select className="rounded border border-slate-300 px-2 py-1 text-sm"
              value={rule.expected_access} onChange={(e) => setRule({ ...rule, expected_access: e.target.value })}>
              <option value="deny">deny</option>
              <option value="allow">allow</option>
            </select>
            <Button variant="secondary" onClick={() => run(() => api.post(`/programs/${p}/permission-rules`, rule), "Add rule")} disabled={!p}>
              Add
            </Button>
          </div>
          <ul className="max-h-32 overflow-auto text-xs">
            {rules.map((r) => (
              <li key={r.id} className="font-mono">
                {r.role}: {r.action} {r.resource} → <span className={r.expected_access === "deny" ? "text-red-600" : "text-green-600"}>{r.expected_access}</span>
              </li>
            ))}
          </ul>
        </Card>

        {/* Module runners */}
        <Card>
          <h3 className="mb-3 font-semibold">Module Runners</h3>
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-2">
              <select className="rounded border border-slate-300 px-2 py-1 text-sm" value={wfKind} onChange={(e) => setWfKind(e.target.value)}>
                {WORKFLOW_KINDS.map((k) => <option key={k}>{k}</option>)}
              </select>
              <Button variant="secondary" onClick={() => run(() => api.post(`/programs/${p}/business-logic/checklist`, { workflow_kind: wfKind }), "Business-logic checklist")} disabled={!p}>
                Generate Checklist
              </Button>
            </div>
            <Button variant="secondary" onClick={() => run(() => api.post(`/programs/${p}/payment-review/checklist`, { observed_params: ["price", "coupon", "plan_id"], sandbox_confirmed: true }), "Payment checklist (sandbox)")} disabled={!p}>
              Payment Review Checklist (sandbox)
            </Button>
            <div className="flex items-center gap-2">
              <input className="flex-1 rounded border border-slate-300 px-2 py-1 text-sm font-mono" placeholder="Authorized repo path"
                value={repoPath} onChange={(e) => setRepoPath(e.target.value)} />
              <Button variant="secondary" onClick={() => run(() => api.post(`/programs/${p}/source-routes/analyze`, { repo_path: repoPath }), "Source route analysis")} disabled={!p}>
                Analyze Source
              </Button>
            </div>
            <div className="rounded border border-slate-200 p-2">
              <div className="mb-1 text-xs font-medium text-slate-500">Access-control compare (dry-run)</div>
              <div className="flex flex-wrap gap-2">
                <input className="w-20 rounded border border-slate-300 px-2 py-1 text-sm" placeholder="acct A id"
                  value={acA} onChange={(e) => setAcA(e.target.value ? Number(e.target.value) : "")} />
                <input className="w-20 rounded border border-slate-300 px-2 py-1 text-sm" placeholder="acct B id"
                  value={acB} onChange={(e) => setAcB(e.target.value ? Number(e.target.value) : "")} />
                <input className="flex-1 rounded border border-slate-300 px-2 py-1 text-sm font-mono" placeholder="object URLs (comma-separated)"
                  value={acTargets} onChange={(e) => setAcTargets(e.target.value)} />
              </div>
              <div className="mt-2">
                <Button variant="secondary"
                  onClick={() => run(() => api.post(`/programs/${p}/access-control/compare`, {
                    account_a_id: acA, account_b_id: acB,
                    target_urls: acTargets.split(",").map((s) => s.trim()).filter(Boolean), dry_run: true,
                  }), "Access-control compare")} disabled={!p}>
                  Compare (dry-run)
                </Button>
              </div>
            </div>
          </div>
        </Card>

        {/* Source routes */}
        <Card>
          <h3 className="mb-3 font-semibold">Source Routes</h3>
          <div className="max-h-40 overflow-auto text-xs">
            {routes.map((r) => (
              <div key={r.id} className="flex items-center justify-between border-b py-1">
                <span className="font-mono">{r.method} {r.route_path}</span>
                <span className={r.has_authentication ? "text-green-600" : "text-red-600"}>
                  {r.has_authentication ? "auth" : "NO AUTH"}
                </span>
              </div>
            ))}
            {routes.length === 0 && <p className="text-slate-400">No source routes analyzed.</p>}
          </div>
        </Card>

        {/* Checklists */}
        <Card>
          <h3 className="mb-3 font-semibold">Generated Checklists</h3>
          <div className="max-h-40 space-y-2 overflow-auto text-sm">
            {checklists.map((c) => (
              <details key={c.id} className="rounded border border-slate-200 p-2">
                <summary className="cursor-pointer">{c.title}</summary>
                <pre className="mt-2 whitespace-pre-wrap text-xs text-slate-600">{c.content_markdown}</pre>
              </details>
            ))}
            {checklists.length === 0 && <p className="text-slate-400">No checklists yet.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
}
