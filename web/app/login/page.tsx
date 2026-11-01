"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, authFailureMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { AuthFrame } from "@/components/auth-frame";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const router = useRouter();
  const { refresh } = useAuth();

  useEffect(() => {
    if (typeof sessionStorage === "undefined") return;
    if (sessionStorage.getItem("aegis_session_expired")) {
      sessionStorage.removeItem("aegis_session_expired");
      setErr("Session expired. Sign in again.");
    }
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await api.login(email, password);
      await refresh();
      // Back to where the session expired; only same-origin paths.
      const next = new URLSearchParams(window.location.search).get("next") ?? "";
      router.replace(next.startsWith("/") && !next.startsWith("//") ? next : "/");
    } catch (e) {
      setErr(authFailureMessage(e, "Sign-in failed. Is the API up?"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame footer="Session cookie, same-origin API. Secrets stay encrypted at rest.">
      <h1 className="page-title text-2xl">Sign in</h1>
      <p className="mt-1.5 text-sm text-dim">Use your Aegis admin account.</p>
      <form onSubmit={onSubmit} className="mt-7 space-y-5">
        {err && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
            {err}
          </p>
        )}
        <label className="block">
          <span className="text-sm font-medium text-dim">Email</span>
          <input
            className="field-line mt-1.5"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoFocus
          />
        </label>
        <label className="block">
          <span className="text-sm font-medium text-dim">Password</span>
          <input
            className="field-line mt-1.5"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        <button className="btn-line mt-2 w-full" disabled={busy} type="submit">
          {busy ? "Signing in…" : "Continue"}
          <span aria-hidden>{busy ? "" : "→"}</span>
        </button>
      </form>
    </AuthFrame>
  );
}
