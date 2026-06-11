// Central API client. All requests target the backend REST API.
// The base URL is configurable via NEXT_PUBLIC_API_URL so the same build works
// in the browser (localhost) and inside docker compose.

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

// Strict authorization: the dashboard authenticates with an API key sent on
// every request. Must match the backend's API_KEY.
const API_KEY = process.env.NEXT_PUBLIC_API_KEY || "dev-local-key";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
      ...(options.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      // The backend returns either {detail: string} or {detail: string[]}.
      detail = Array.isArray(body.detail) ? body.detail.join("; ") : body.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

export const api = {
  get: <T>(p: string) => request<T>(p),
  post: <T>(p: string, body?: unknown) =>
    request<T>(p, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  patch: <T>(p: string, body?: unknown) =>
    request<T>(p, { method: "PATCH", body: body ? JSON.stringify(body) : undefined }),
  del: <T>(p: string) => request<T>(p, { method: "DELETE" }),
};

// ---- Types -------------------------------------------------------------
export interface Program {
  id: number;
  name: string;
  description?: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface ScopeItem {
  id: number;
  program_id: number;
  scope_type: string;
  value: string;
  is_allowed: boolean;
  notes?: string;
  created_at: string;
}

export interface Asset {
  id: number;
  program_id: number;
  asset_type: string;
  value: string;
  ip_address?: string;
  port?: number;
  scheme?: string;
  status: string;
  technologies?: string;
  risk_score: number;
  last_seen?: string;
  created_at: string;
}

export interface ScanJob {
  id: number;
  program_id: number;
  job_type: string;
  status: string;
  target: string;
  dry_run: boolean;
  started_at?: string;
  finished_at?: string;
  logs?: string;
  error_message?: string;
  created_at: string;
}

export interface Finding {
  id: number;
  program_id: number;
  asset_id?: number;
  title: string;
  description?: string;
  severity: string;
  confidence: string;
  status: string;
  category?: string;
  cwe?: string;
  owasp?: string;
  evidence_summary?: string;
  impact?: string;
  remediation?: string;
  scanner_name?: string;
  raw_output?: string;
  ai_summary?: string;
  manual_review_required: boolean;
  created_at: string;
  updated_at: string;
}

export interface Report {
  id: number;
  program_id: number;
  finding_id: number;
  title: string;
  content_markdown: string;
  file_path?: string;
  created_at: string;
}

export interface Overview {
  total_programs: number;
  total_assets: number;
  open_findings_by_severity: Record<string, number>;
  running_scans: number;
  needs_review_findings: number;
  kill_switch_enabled: boolean;
  recent_scan_jobs: ScanJob[];
  top_risky_assets: Asset[];
}

export interface AuditLog {
  id: number;
  actor: string;
  action: string;
  target?: string;
  decision: string;
  detail?: string;
  created_at: string;
}

export interface Settings {
  app_name: string;
  dry_run_default: boolean;
  kill_switch_enabled: boolean;
  auth_enabled: boolean;
  allow_private_targets: boolean;
  scanner_rate_limit_per_sec: number;
  enable_vulnerable_target: boolean;
  allowed_scan_types: string[];
  forbidden_scan_types: string[];
}
