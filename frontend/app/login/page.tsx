"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login, auth } from "@/lib/api";
import { Card, Button } from "@/components/ui";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@localhost");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
      router.push("/");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto mt-16 max-w-md">
      <div className="mb-6 text-center">
        <div className="text-2xl font-bold text-brand">AutoBugHunter</div>
        <div className="text-sm text-slate-400">authorized scanning only</div>
      </div>
      <Card>
        <h1 className="mb-4 text-lg font-semibold">Sign in</h1>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label className="block text-xs text-slate-500">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-500">Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <Button type="submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <p className="mt-4 text-xs text-slate-400">
          Demo: <code>admin@localhost</code> / <code>admin12345</code>. Roles: triager,
          researcher, viewer (password <code>demo12345</code>). Or skip login to use the demo
          API key.
        </p>
        {auth.isLoggedIn() && (
          <button
            onClick={() => {
              auth.clear();
              location.reload();
            }}
            className="mt-3 text-xs text-red-500 hover:underline"
          >
            Log out current session
          </button>
        )}
      </Card>
    </div>
  );
}
