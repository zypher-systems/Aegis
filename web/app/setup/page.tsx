"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { api, authFailureMessage } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { AuthFrame } from "@/components/auth-frame";

export default function SetupPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const router = useRouter();
  const { refresh } = useAuth();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    if (password !== confirm) {
      setErr("Passwords do not match.");
      return;
    }
    if (password.length < 10) {
      setErr("Password must be at least 10 characters.");
      return;
    }
    setBusy(true);
    try {
      await api.setup(email, name, password);
      await refresh();
      router.replace("/onboarding");
    } catch (e2) {
      setErr(authFailureMessage(e2, "Setup failed."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame footer="This account has full control of the proxy. Store the password safely.">
      <h1 className="page-title text-2xl">Create the first admin</h1>
      <p className="mt-1.5 text-sm text-dim">This account manages every host, certificate and policy.</p>
      <form onSubmit={onSubmit} className="mt-7 space-y-5">
        {err && (
          <p role="alert" className="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
            {err}
          </p>
        )}
        <label className="block">
          <span className="text-sm font-medium text-dim">Name</span>
          <input
            className="field-line mt-1.5"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />
        </label>
        <label className="block">
          <span className="text-sm font-medium text-dim">Email</span>
          <input
            className="field-line mt-1.5"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </label>
        <label className="block">
          <span className="text-sm font-medium text-dim">Password</span>
          <input
            className="field-line mt-1.5"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        <label className="block">
          <span className="text-sm font-medium text-dim">Confirm</span>
          <input
            className="field-line mt-1.5"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
        </label>
        <button className="btn-line mt-2 w-full" disabled={busy} type="submit">
          {busy ? "Creating…" : "Continue"}
          <span aria-hidden>{busy ? "" : "→"}</span>
        </button>
      </form>
    </AuthFrame>
  );
}
