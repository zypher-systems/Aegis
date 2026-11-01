"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Node } from "@/lib/types";
import { POLL_MS } from "@/lib/poll";
import { StatusDot } from "@/components/ui";

// Fleet health from the node list. `compact` renders a single dot with the
// summary as its accessible label (the rail); the default is dot + text.
export function NodeStatus({ compact = false }: { compact?: boolean }) {
  const [nodes, setNodes] = useState<Node[] | null>(null);
  const [failed, setFailed] = useState(false);

  async function load() {
    try {
      setNodes(await api.nodes());
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, []);

  const online = (nodes ?? []).filter((n) => n.online ?? isOnline(n.last_seen_at)).length;
  const total = nodes?.length ?? 0;

  const tone = failed ? "warn" : nodes === null ? "neutral" : online > 0 && online === total ? "ok" : online > 0 ? "warn" : "danger";
  const label = failed
    ? "Node status unavailable"
    : nodes === null
      ? "Checking nodes"
      : `${online}/${total} node${total === 1 ? "" : "s"} online`;
  if (compact) {
    const bg = { ok: "bg-ok", warn: "bg-warn", danger: "bg-danger", neutral: "bg-faint", accent: "bg-accent" }[tone];
    return (
      <span role="status" aria-label={label} title={label} className="relative inline-flex h-2.5 w-2.5">
        {tone === "ok" && <span className={`absolute inset-0 rounded-full ${bg} opacity-40 pulse`} />}
        <span className={`relative inline-block h-2.5 w-2.5 rounded-full ${bg}`} />
      </span>
    );
  }
  return (
    <div className="text-xs text-dim">
      <StatusDot tone={failed ? "warn" : nodes === null ? "neutral" : online > 0 ? "ok" : "danger"}>
        {failed
          ? "Node status unavailable"
          : nodes === null
            ? "…"
            : `${online}/${total} node${total === 1 ? "" : "s"} online`}
      </StatusDot>
    </div>
  );
}

function isOnline(lastSeen?: string): boolean {
  if (!lastSeen) return false;
  // Consider a node online if it checked in within the last 60s (it holds a
  // persistent config stream, so last_seen updates on connect).
  return Date.now() - new Date(lastSeen).getTime() < 60_000;
}
