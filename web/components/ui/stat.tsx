import Link from "next/link";
import { ReactNode } from "react";
import type { Tone } from "./badge";

const VALUE_TONE: Record<Tone, string> = {
  neutral: "text-fg",
  accent: "text-accent",
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
};

// Stat card: label, big display-face number, optional sub-line. Links when
// href is set.
export function Stat({
  label,
  value,
  sub,
  tone = "neutral",
  href,
}: {
  label: ReactNode;
  value: ReactNode;
  sub?: ReactNode;
  tone?: Tone;
  href?: string;
}) {
  const body = (
    <>
      <div className="text-sm font-medium text-dim">{label}</div>
      <div className={`display-num mt-2 text-3xl ${VALUE_TONE[tone]}`}>{value}</div>
      {sub && <div className="mt-1.5 text-xs text-faint">{sub}</div>}
    </>
  );
  if (href) {
    return (
      <Link href={href} className="card group block p-5 transition-colors hover:border-accent/50">
        {body}
      </Link>
    );
  }
  return <div className="card p-5">{body}</div>;
}

export function StatGrid({ children, cols = 4 }: { children: ReactNode; cols?: 3 | 4 | 5 }) {
  const lg = { 3: "lg:grid-cols-3", 4: "lg:grid-cols-4", 5: "lg:grid-cols-5" }[cols];
  return <div className={`grid grid-cols-2 gap-4 ${lg}`}>{children}</div>;
}
