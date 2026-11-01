import { ReactNode } from "react";

export type Tone = "neutral" | "accent" | "ok" | "warn" | "danger";

const TONES: Record<Tone, string> = {
  neutral: "border-border-strong bg-panel-2 text-dim",
  accent: "border-accent/40 bg-accent/10 text-accent",
  ok: "border-ok/40 bg-ok/10 text-ok",
  warn: "border-warn/40 bg-warn/10 text-warn",
  danger: "border-danger/40 bg-danger/10 text-danger",
};

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center whitespace-nowrap rounded-md border px-2 py-0.5 text-[11px] font-bold leading-4 ${TONES[tone]}`}
    >
      {children}
    </span>
  );
}

// Status pill: dot + label on a tinted ground (Healthy, Down, …).
export function StatusPill({ tone, children }: { tone: Tone; children: ReactNode }) {
  const TINT: Record<Tone, string> = {
    neutral: "bg-panel-2 text-dim",
    accent: "bg-accent/10 text-accent",
    ok: "bg-ok/10 text-ok",
    warn: "bg-warn/10 text-warn",
    danger: "bg-danger/10 text-danger",
  };
  const DOT: Record<Tone, string> = {
    neutral: "bg-faint",
    accent: "bg-accent",
    ok: "bg-ok",
    warn: "bg-warn",
    danger: "bg-danger",
  };
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-bold ${TINT[tone]}`}>
      <span aria-hidden className={`h-1.5 w-1.5 rounded-full ${DOT[tone]}`} />
      {children}
    </span>
  );
}

// Coloured dot + label for live state (online, offline, …).
export function StatusDot({ tone, children }: { tone: Tone; children: ReactNode }) {
  const bg: Record<Tone, string> = {
    neutral: "bg-faint",
    accent: "bg-accent",
    ok: "bg-ok",
    warn: "bg-warn",
    danger: "bg-danger",
  };
  return (
    <span className="inline-flex items-center gap-2">
      <span aria-hidden className={`inline-block h-1.5 w-1.5 rounded-full ${bg[tone]}`} />
      <span>{children}</span>
    </span>
  );
}
