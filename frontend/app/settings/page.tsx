"use client";

import { useEffect, useState } from "react";
import { api, Settings } from "@/lib/api";
import { Card, Button, PageHeader } from "@/components/ui";

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => api.get<Settings>("/settings").then(setSettings);
  useEffect(() => {
    load();
  }, []);

  const toggleKill = async () => {
    if (!settings) return;
    const enabled = !settings.kill_switch_enabled;
    await api.post("/settings/kill-switch", { enabled });
    setMsg(enabled ? "Kill switch ENGAGED — all scanning disabled." : "Kill switch released.");
    load();
  };

  if (!settings) return <p className="text-slate-400">Loading…</p>;

  return (
    <div>
      <PageHeader title="Settings" subtitle="Safety controls and platform configuration" />

      <Card className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold">Global Kill Switch</h3>
            <p className="text-sm text-slate-500">
              When engaged, no new scans can be queued or executed across the platform.
            </p>
          </div>
          <Button variant={settings.kill_switch_enabled ? "danger" : "secondary"} onClick={toggleKill}>
            {settings.kill_switch_enabled ? "🛑 Engaged — Release" : "Engage Kill Switch"}
          </Button>
        </div>
        {msg && <p className="mt-3 text-sm text-slate-600">{msg}</p>}
      </Card>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <Card>
          <h3 className="mb-3 font-semibold">Safety Configuration</h3>
          <dl className="space-y-2 text-sm">
            <Row label="Dry-run by default" value={settings.dry_run_default ? "ON ✅" : "OFF ⚠️"} />
            <Row label="API-key authorization" value={settings.auth_enabled ? "enabled ✅" : "disabled ⚠️"} />
            <Row label="Allow private targets" value={settings.allow_private_targets ? "yes" : "no"} />
            <Row label="Scanner rate limit" value={`${settings.scanner_rate_limit_per_sec}/sec`} />
            <Row
              label="Local vulnerable target"
              value={settings.enable_vulnerable_target ? "enabled" : "disabled (default)"}
            />
          </dl>
        </Card>

        <Card>
          <h3 className="mb-3 font-semibold">Scan Type Policy</h3>
          <p className="text-xs text-slate-500">Allowed (passive/safe):</p>
          <div className="mb-3 mt-1 flex flex-wrap gap-1">
            {settings.allowed_scan_types.map((t) => (
              <span key={t} className="rounded-full bg-green-100 px-2 py-0.5 text-xs text-green-800">
                {t}
              </span>
            ))}
          </div>
          <p className="text-xs text-slate-500">Forbidden (always rejected):</p>
          <div className="mt-1 flex flex-wrap gap-1">
            {settings.forbidden_scan_types.map((t) => (
              <span key={t} className="rounded-full bg-red-100 px-2 py-0.5 text-xs text-red-800">
                {t}
              </span>
            ))}
          </div>
        </Card>
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
