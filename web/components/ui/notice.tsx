import { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Info, OctagonAlert } from "lucide-react";
import type { Tone } from "./badge";

const TONES: Record<Exclude<Tone, "neutral">, { box: string; title: string; Icon: typeof Info }> = {
  accent: { box: "border-accent/30 bg-accent/5", title: "text-accent", Icon: Info },
  ok: { box: "border-ok/30 bg-ok/5", title: "text-ok", Icon: CheckCircle2 },
  warn: { box: "border-warn/30 bg-warn/5", title: "text-warn", Icon: AlertTriangle },
  danger: { box: "border-danger/30 bg-danger/10", title: "text-danger", Icon: OctagonAlert },
};

// Callout for state the operator should act on (expiring cert, self-signed
// mode, licence lapse). Plain-language title, optional detail and action.
export function Notice({
  tone = "warn",
  title,
  children,
  action,
}: {
  tone?: Exclude<Tone, "neutral">;
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
}) {
  const t = TONES[tone];
  return (
    <div role={tone === "danger" ? "alert" : "status"} className={`rounded-xl border px-4 py-3 text-sm ${t.box}`}>
      <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
        <t.Icon size={18} aria-hidden className={`mt-px shrink-0 ${t.title}`} />
        <div className="min-w-0 flex-1">
          <div className={`font-medium ${t.title}`}>{title}</div>
          {children && <div className="mt-1 text-dim">{children}</div>}
        </div>
        {action && <div className="shrink-0">{action}</div>}
      </div>
    </div>
  );
}
