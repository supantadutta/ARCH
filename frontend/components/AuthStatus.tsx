"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { auth } from "@/lib/api";

export function AuthStatus() {
  const [email, setEmail] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);

  useEffect(() => {
    setEmail(auth.email());
    setRole(auth.role());
  }, []);

  if (auth.isLoggedIn()) {
    return (
      <div className="mt-4 rounded-lg bg-slate-100 p-3 text-xs text-slate-600">
        <div className="font-medium text-slate-800">{email}</div>
        <div className="capitalize text-slate-500">role: {role}</div>
        <button
          onClick={() => {
            auth.clear();
            location.href = "/login";
          }}
          className="mt-2 text-red-500 hover:underline"
        >
          Log out
        </button>
      </div>
    );
  }
  return (
    <Link
      href="/login"
      className="mt-4 block rounded-lg bg-brand px-3 py-2 text-center text-xs font-medium text-white hover:bg-brand-dark"
    >
      Sign in (using demo API key)
    </Link>
  );
}
