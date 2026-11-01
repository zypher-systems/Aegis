import { ReactNode } from "react";
import { Globe2, Lock, ShieldCheck } from "lucide-react";
import { EdgeScene } from "./edge-scene";
import { LogoMark, Wordmark } from "./logo";

const POINTS = [
  { icon: ShieldCheck, title: "OWASP CRS web application firewall", body: "Coraza inspects every proxied request." },
  { icon: Globe2, title: "CrowdSec community blocklists", body: "Known attackers are stopped at the edge and the host firewall." },
  { icon: Lock, title: "Automatic TLS", body: "Let’s Encrypt over HTTP-01 or Cloudflare DNS-01, renewed for you." },
];

// Sign-in and first-run frame: brand panel on the left (desktop), the form
// on a card on the right.
export function AuthFrame({
  children,
  footer,
}: {
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="auth-surface grid min-h-screen lg:grid-cols-[minmax(0,1.15fr)_minmax(26rem,1fr)]">
      <section className="hero-glow relative hidden min-h-screen flex-col justify-between overflow-hidden border-r border-border px-12 py-10 lg:flex xl:px-16">
        <Wordmark size={30} />
        <div className="max-w-xl">
          <h2 className="display-num text-[2.75rem] leading-[1.05]">
            The security-first edge
            <br />
            <span className="text-faint">for everything you run.</span>
          </h2>
          <ul className="mt-8 space-y-5">
            {POINTS.map((p) => (
              <li key={p.title} className="flex gap-3.5">
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-accent/10 text-accent">
                  <p.icon size={18} aria-hidden />
                </span>
                <span>
                  <span className="block text-sm font-semibold">{p.title}</span>
                  <span className="block text-sm text-dim">{p.body}</span>
                </span>
              </li>
            ))}
          </ul>
          <div className="card mt-10 p-6">
            <EdgeScene />
          </div>
        </div>
        <p className="text-xs text-faint">Clients reach the edge. Config arrives over mTLS. Upstreams never face the internet.</p>
      </section>

      <section className="flex min-h-screen flex-col items-center justify-center px-5 py-12 sm:px-10">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex justify-center lg:hidden">
            <LogoMark size={44} />
          </div>
          <div className="card p-7 sm:p-8">{children}</div>
          {footer ? <p className="mt-6 text-center text-xs leading-relaxed text-faint">{footer}</p> : null}
        </div>
      </section>
    </div>
  );
}
