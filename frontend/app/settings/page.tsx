"use client";

import { useEffect, useState } from "react";
import { api, Settings, ScannerStatusResponse } from "@/lib/api";
import { Card, Button, PageHeader } from "@/components/ui";

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [scanners, setScanners] = useState<ScannerStatusResponse | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => {
    api.get<Settings>("/settings").then(setSettings);
    api.get<ScannerStatusResponse>("/settings/scanners").then(setScanners);
  };
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

      {scanners && (
        <Card className="mt-6">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="font-semibold">External Scanners</h3>
            <span className="text-xs text-slate-400">
              timeout {scanners.timeout_seconds}s · dry-run default{" "}
              {scanners.dry_run_default ? "ON" : "OFF"}
            </span>
          </div>
          <p className="mb-3 text-xs text-slate-500">
            A scanner runs for real only when it is <b>enabled</b> in settings <b>and</b> its
            binary is <b>installed</b>. All external scanners are opt-in and disabled by default.
          </p>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b text-left text-slate-500">
                <th className="py-2">Scanner</th>
                <th>Target</th>
                <th>Enabled</th>
                <th>Installed</th>
                <th>Runnable</th>
                <th>Default safe mode</th>
              </tr>
            </thead>
            <tbody>
              {scanners.scanners.map((s) => (
                <tr key={s.name} className="border-b last:border-0">
                  <td className="py-2 font-mono">{s.name}</td>
                  <td className="text-slate-500">{s.target_kind}</td>
                  <td>{s.enabled ? "✅" : "—"}</td>
                  <td>{s.installed ? "✅" : "—"}</td>
                  <td>{s.runnable ? "✅ yes" : "no"}</td>
                  <td className="text-slate-500">{s.default_mode}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {scanners.authorized_scan_paths.length > 0 ? (
            <p className="mt-3 text-xs text-slate-500">
              Authorized local scan paths:{" "}
              <span className="font-mono">{scanners.authorized_scan_paths.join(", ")}</span>
            </p>
          ) : (
            <p className="mt-3 text-xs text-slate-400">
              No authorized local scan paths configured — semgrep/gitleaks/trivy path scanning is
              disabled.
            </p>
          )}
        </Card>
      )}
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
