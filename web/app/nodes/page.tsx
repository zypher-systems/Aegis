"use client";

import { useEffect, useState } from "react";
import { Check, Copy, Server, TerminalSquare } from "lucide-react";
import { api, isUnauthorized } from "@/lib/api";
import type { Node } from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import { ActionMenu, Dialog, ErrorState, Loading, PageHeader, StatusPill, type Tone } from "@/components/ui";
import { POLL_MS } from "@/lib/poll";
import { daysUntil, fmtDate, fmtDateTime, fmtMs, fmtRelative } from "@/lib/format";

// Placeholders only: the real token lives in Settings and .env, never here.
const ENROL_SNIPPET = `docker run -d --name aegis-proxy \\
  -e AEGIS_CONTROL_PLANE=<control-plane>:9444 \\
  -e AEGIS_NODE_PLANE=<control-plane>:9443 \\
  -e AEGIS_ENROLL_TOKEN=<enrollment token> \\
  -e AEGIS_NODE_NAME=edge-2 \\
  -v aegis-proxy:/var/lib/aegis-proxy \\
  -p 80:80 -p 443:443 \\
  <aegis-proxy image>`;

export default function NodesPage() {
  const [nodes, setNodes] = useState<Node[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selected, setSelected] = useState<{ node: Node; revoke: boolean } | null>(null);

  async function load() {
    try {
      setNodes(await api.nodes());
      setErr(null);
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load nodes");
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, []);

  const active = (nodes ?? []).filter((n) => !n.revoked);
  const online = active.filter((n) => n.online).length;

  return (
    <AppShell>
      <PageHeader
        title="Nodes"
        description={
          nodes === null
            ? "Edge nodes that serve your hosts. Each checks in every 20 seconds on the config stream."
            : `${online} of ${active.length} edge node${active.length === 1 ? "" : "s"} online. Each checks in every 20 seconds on the config stream.`
        }
      />
      {err && (
        <div className="mt-6">
          <ErrorState message={err} onRetry={load} />
        </div>
      )}

      <div className="mt-6 grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
        {nodes === null
          ? !err && (
              <div className="card card-pad">
                <Loading rows={4} label="Loading nodes" />
              </div>
            )
          : nodes.map((n) => (
              <NodeCard
                onRename={async () => {
                  const name = window.prompt("New name for this node", n.name);
                  if (name === null || !name.trim() || name.trim() === n.name) return;
                  try {
                    await api.renameNode(n.id, name.trim());
                    await load();
                  } catch (e) {
                    setErr(e instanceof Error ? e.message : "Rename failed");
                  }
                }}
                key={n.id}
                node={n}
                onOpen={() => setSelected({ node: n, revoke: false })}
                onRevoke={() => setSelected({ node: n, revoke: true })}
              />
            ))}
        <EnrolCard empty={nodes !== null && nodes.length === 0} />
      </div>

      {selected && (
        <NodeDialog
          node={selected.node}
          startRevoke={selected.revoke}
          onClose={() => setSelected(null)}
          onRevoked={async () => {
            setSelected(null);
            await load();
          }}
        />
      )}
    </AppShell>
  );
}

function nodeState(n: Node): { label: string; tone: Tone } {
  if (n.revoked) return { label: "Revoked", tone: "danger" };
  if (n.online) return { label: "Online", tone: "ok" };
  return { label: "Offline", tone: "warn" };
}

function NodeCard({ node, onOpen, onRevoke, onRename }: { node: Node; onOpen: () => void; onRevoke: () => void; onRename: () => void }) {
  const st = nodeState(node);
  const certDays = daysUntil(node.cert_expires_at);
  const certTone = certDays === null ? "text-dim" : certDays < 0 ? "text-danger" : certDays <= 14 ? "text-warn" : "text-dim";
  const rps = node.rps ?? 0;
  return (
    <article className={`card flex flex-col gap-4 p-5 ${node.revoked ? "opacity-60" : ""}`}>
      <div className="flex items-start gap-3">
        <div aria-hidden className="flex h-10 w-10 shrink-0 items-center justify-center rounded-[11px] border border-border-strong bg-panel-2 text-dim">
          <Server size={18} />
        </div>
        <div className="min-w-0 flex-1">
          <button type="button" onClick={onOpen} className="block max-w-full truncate text-left font-display text-base font-semibold hover:text-accent">
            {node.name}
          </button>
          <div className="mt-0.5 font-mono text-xs text-faint">{node.agent_version ? `v${node.agent_version.replace(/^v/, "")}` : "version unknown"}</div>
        </div>
        <StatusPill tone={st.tone}>{st.label}</StatusPill>
        <ActionMenu
          label={`Actions for ${node.name}`}
          items={[
            { label: "Details", onSelect: onOpen },
            { label: "Rename", onSelect: onRename },
            ...(node.revoked ? [] : [{ label: "Revoke certificate", onSelect: onRevoke, danger: true }]),
          ]}
        />
      </div>

      <dl className="grid grid-cols-3 gap-3 rounded-xl border border-border bg-bg/60 p-3">
        <Metric label="Req/s" value={rps >= 10 ? rps.toFixed(0) : rps.toFixed(2)} />
        <Metric label="p50" value={fmtMs(node.p50_ms ?? 0)} />
        <Metric label="p99" value={fmtMs(node.p99_ms ?? 0)} />
      </dl>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-faint">
        <span title={fmtDateTime(node.last_seen_at, "never")}>
          Last seen <span className="text-dim">{fmtRelative(node.last_seen_at)}</span>
        </span>
        <span className="ml-auto" title={fmtDate(node.cert_expires_at)}>
          Client cert{" "}
          <span className={certTone}>
            {certDays === null ? "—" : certDays < 0 ? `expired ${-certDays}d ago` : `${certDays}d left`}
          </span>
        </span>
      </div>
    </article>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold text-faint">{label}</dt>
      <dd className="mt-0.5 font-mono text-sm text-fg">{value}</dd>
    </div>
  );
}

function EnrolCard({ empty }: { empty: boolean }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(ENROL_SNIPPET);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard unavailable; the text is selectable */
    }
  }
  return (
    <section
      aria-labelledby="enrol-h"
      className={`card flex flex-col gap-3 border-dashed p-5 ${empty ? "md:col-span-2 2xl:col-span-3" : ""}`}
    >
      <div className="flex items-center gap-2.5">
        <TerminalSquare size={18} className="text-accent" aria-hidden />
        <h2 id="enrol-h" className="section-title">
          {empty ? "Enrol your first edge node" : "Enrol a node"}
        </h2>
      </div>
      <p className="text-sm text-dim">
        A proxy enrols on first boot with the enrollment token from Settings, receives an mTLS client certificate from
        the internal CA, then pulls config over the node plane. Replace the placeholders below.
      </p>
      <div className="relative">
        <pre
          className="overflow-x-auto rounded-xl border border-border bg-bg p-3.5 pr-12 font-mono text-xs leading-relaxed text-dim"
          style={{ fontVariantLigatures: "none" }}
        >
          {ENROL_SNIPPET}
        </pre>
        <button
          type="button"
          onClick={copy}
          aria-label={copied ? "Copied" : "Copy command"}
          className="absolute right-2 top-2 flex h-8 w-8 items-center justify-center rounded-lg text-faint hover:bg-panel-2 hover:text-fg"
        >
          {copied ? <Check size={16} className="text-ok" aria-hidden /> : <Copy size={16} aria-hidden />}
        </button>
      </div>
      <a href="/settings" className="text-sm font-semibold text-accent hover:text-fg">
        Generate an enrolment token in Settings
      </a>
    </section>
  );
}

function NodeDialog({
  node,
  startRevoke,
  onClose,
  onRevoked,
}: {
  node: Node;
  startRevoke: boolean;
  onClose: () => void;
  onRevoked: () => void | Promise<void>;
}) {
  const [confirmRevoke, setConfirmRevoke] = useState(startRevoke && !node.revoked);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const st = nodeState(node);

  async function onRevoke() {
    setBusy(true);
    setErr(null);
    try {
      await api.revokeNode(node.id);
      await onRevoked();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Revoke failed.");
      setConfirmRevoke(false);
    } finally {
      setBusy(false);
    }
  }

  const footer = node.revoked ? (
    <button type="button" className="btn btn-secondary" onClick={onClose}>
      Close
    </button>
  ) : confirmRevoke ? (
    <>
      <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setConfirmRevoke(false)}>
        Cancel
      </button>
      <button type="button" className="btn bg-danger text-ink hover:bg-danger/90" disabled={busy} onClick={onRevoke}>
        {busy ? "Revoking…" : "Revoke node"}
      </button>
    </>
  ) : (
    <>
      <button type="button" className="btn btn-danger mr-auto" disabled={busy} onClick={() => setConfirmRevoke(true)}>
        Revoke
      </button>
      <button type="button" className="btn btn-secondary" onClick={onClose}>
        Close
      </button>
    </>
  );

  return (
    <Dialog
      size="sm"
      title={node.name}
      description="Client certificate identity. Revoking refuses the certificate immediately; enrol a replacement with a token generated in Settings."
      onClose={onClose}
      footer={footer}
    >
      <dl className="space-y-3 text-sm">
        <div className="flex items-center justify-between gap-4">
          <dt className="text-faint">Status</dt>
          <dd>
            <StatusPill tone={st.tone}>{st.label}</StatusPill>
          </dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-faint">Agent</dt>
          <dd className="font-mono text-dim">{node.agent_version || "—"}</dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-faint">Last seen</dt>
          <dd className="text-right text-dim">
            {fmtDateTime(node.last_seen_at, "never")}
            {node.last_seen_at && <span className="text-faint"> · {fmtRelative(node.last_seen_at)}</span>}
          </dd>
        </div>
        <div className="flex items-center justify-between gap-4">
          <dt className="text-faint">Cert expires</dt>
          <dd className="font-mono text-dim">{fmtDate(node.cert_expires_at)}</dd>
        </div>
      </dl>
      {err && <p className="mt-4 text-sm text-danger">{err}</p>}
      {confirmRevoke && !node.revoked && (
        <p className="mt-6 rounded-xl border border-danger/30 bg-danger/5 p-3.5 text-sm text-dim">
          Revoke <span className="text-fg">{node.name}</span>? Its client certificate will be refused on the next handshake and the
          config stream will drop. Wipe the node&apos;s stored identity before it can enrol again.
        </p>
      )}
    </Dialog>
  );
}
