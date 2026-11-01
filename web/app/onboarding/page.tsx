"use client";

import { ReactNode, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, isUnauthorized } from "@/lib/api";
import type { Certificate, Host, Node } from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { PageHeader } from "@/components/ui";

const DONE_KEY = "aegis.onboarded";

export default function OnboardingPage() {
  const router = useRouter();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [certs, setCerts] = useState<Certificate[] | null>(null);
  const [nodes, setNodes] = useState<Node[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    try {
      const [h, c, n] = await Promise.all([api.hosts(), api.certificates(), api.nodes()]);
      setHosts(h);
      setCerts(c);
      setNodes(n);
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load");
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  const hasHost = (hosts?.length ?? 0) > 0;
  const hasCert = (certs?.length ?? 0) > 0;
  const nodeOnline = (nodes ?? []).some((n) => n.online);
  const done = hasHost && nodeOnline;

  function finish() {
    try { localStorage.setItem(DONE_KEY, "1"); } catch { /* ignore */ }
    router.replace("/");
  }

  return (
    <AppShell>
      <PageHeader title="Get Aegis live" description="Three checks. You can skip and come back — nothing is gated." />
      <div className="max-w-xl">
        {err && <p className="mt-4 text-sm text-danger">{err}</p>}

        <ol className="mt-10">
          <Step n={1} done={hasHost} title="Create a host" body="Point a domain at an upstream. Use TLS none for local demo.local.">
            <Link href="/hosts" className="btn btn-primary">Open Hosts →</Link>
          </Step>
          <Step n={2} done={hasCert} title="Issue or upload a certificate" body="Optional for TLS none. Request Let's Encrypt or upload PEM before going public.">
            <Link href="/certificates" className="btn btn-primary">Open Certificates →</Link>
          </Step>
          <Step n={3} done={nodeOnline} title="Confirm a node is online" body="The proxy enrolls on boot with AEGIS_ENROLL_TOKEN. Last-seen should stay fresh.">
            <Link href="/nodes" className="btn btn-primary">Open Nodes →</Link>
          </Step>
        </ol>

        <div className="mt-10 flex items-center gap-5">
          <button className="btn btn-primary" disabled={!done} onClick={finish}>
            {done ? "Enter dashboard →" : "Waiting on host + node…"}
          </button>
          <button className="btn btn-ghost" onClick={finish}>Skip for now</button>
        </div>
      </div>
    </AppShell>
  );
}

function Step({
  n, done, title, body, children,
}: {
  n: number; done: boolean; title: string; body: string; children: ReactNode;
}) {
  return (
    <li className="flex gap-4 border-t border-border py-6">
      <span className={`mt-0.5 w-5 shrink-0 text-sm ${done ? "text-ok" : "text-faint"}`}>
        {done ? "✓" : n}
      </span>
      <div className="min-w-0 flex-1">
        <div className="font-medium">{title}</div>
        <p className="mt-1 text-sm text-dim">{body}</p>
        <div className="mt-3">{children}</div>
      </div>
    </li>
  );
}
