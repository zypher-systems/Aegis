"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ReactNode, useEffect, useRef, useState } from "react";
import {
  Activity,
  Globe,
  KeyRound,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  Moon,
  Server,
  Settings,
  ShieldCheck,
  Sun,
  X,
  type LucideIcon,
} from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { NodeStatus } from "@/components/node-status";
import { LogoMark, Wordmark } from "@/components/logo";

type NavItem = { href: string; label: string; icon: LucideIcon; exact?: boolean };

const NAV: NavItem[] = [
  { href: "/", label: "Overview", icon: LayoutDashboard, exact: true },
  { href: "/hosts", label: "Hosts", icon: Globe },
  { href: "/waf", label: "WAF policies", icon: ShieldCheck },
  { href: "/analytics", label: "Analytics", icon: Activity },
  { href: "/certificates", label: "Certificates", icon: Lock },
  { href: "/access-lists", label: "Access lists", icon: KeyRound },
  { href: "/nodes", label: "Nodes", icon: Server },
];
const SETTINGS: NavItem = { href: "/settings", label: "Settings", icon: Settings };

function isActive(item: NavItem, pathname: string) {
  return item.exact ? pathname === item.href : pathname.startsWith(item.href);
}

// One rail button: icon only, with a label that appears on hover and on
// keyboard focus (and is the accessible name either way).
function RailLink({ item, pathname }: { item: NavItem; pathname: string }) {
  const active = isActive(item, pathname);
  const Icon = item.icon;
  return (
    <Link
      href={item.href}
      aria-label={item.label}
      aria-current={active ? "page" : undefined}
      className={`group relative flex h-11 w-11 items-center justify-center rounded-xl transition-colors ${
        active ? "bg-accent/10 text-accent" : "text-faint hover:bg-panel-2 hover:text-fg"
      }`}
    >
      <Icon size={20} strokeWidth={1.8} aria-hidden />
      <span
        aria-hidden
        className="pointer-events-none absolute left-full z-50 ml-3 whitespace-nowrap rounded-lg border border-border-strong bg-panel-2 px-2.5 py-1.5 text-xs font-semibold text-fg opacity-0 shadow-lg transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100"
      >
        {item.label}
      </span>
    </Link>
  );
}

// Switches between the dark default and the light alternate.
function ThemeToggle({ className, role }: { className: string; role?: "menuitem" }) {
  const { theme, toggle } = useTheme();
  const Icon = theme === "dark" ? Sun : Moon;
  return (
    <button type="button" role={role} onClick={toggle} className={className}>
      <Icon size={16} aria-hidden /> {theme === "dark" ? "Light theme" : "Dark theme"}
    </button>
  );
}

function UserMenu({ name, email, role, version, onSignOut }: { name: string; email: string; role: string; version: string; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  const initials = (name || email)
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase())
    .join("");
  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account: ${name || email}`}
        onClick={() => setOpen((v) => !v)}
        className="flex h-9 w-9 items-center justify-center rounded-full border border-border-strong bg-panel-2 text-xs font-bold text-dim hover:text-fg"
      >
        {initials || "?"}
      </button>
      {open && (
        <div
          role="menu"
          className="fade-in absolute bottom-0 left-full z-50 ml-3 w-60 rounded-xl border border-border-strong bg-panel-2 p-2 shadow-2xl md:bottom-0"
        >
          <div className="px-2.5 py-2">
            <div className="truncate text-sm font-semibold">{name || email}</div>
            <div className="truncate text-xs text-faint">{email}</div>
            <div className="mt-1 text-xs text-faint">
              {role} · Aegis <span className="font-mono">{version || "—"}</span>
            </div>
          </div>
          <div className="my-1 h-px bg-border" />
          <ThemeToggle
            role="menuitem"
            className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-sm text-dim hover:bg-panel hover:text-fg"
          />
          <button
            type="button"
            role="menuitem"
            onClick={onSignOut}
            className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-sm text-dim hover:bg-panel hover:text-fg"
          >
            <LogOut size={16} aria-hidden /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { user, loading, logout } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const [menu, setMenu] = useState(false);
  const [version, setVersion] = useState("");

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [user, loading, router]);

  useEffect(() => {
    setMenu(false);
  }, [pathname]);

  useEffect(() => {
    if (!menu) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenu(false);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [menu]);

  useEffect(() => {
    api.healthz().then((h) => setVersion(h.version || "")).catch(() => undefined);
  }, []);

  if (loading || !user) {
    return (
      <div role="status" className="flex min-h-screen items-center justify-center text-sm text-dim">
        <LogoMark size={28} className="pulse" />
        <span className="sr-only">Loading</span>
      </div>
    );
  }

  const signOut = async () => {
    await logout();
    router.replace("/login");
  };

  return (
    <div className="flex min-h-screen">
      <nav
        aria-label="Main"
        className="sticky top-0 hidden h-screen w-[76px] shrink-0 flex-col items-center gap-1.5 border-r border-border bg-rail py-5 md:flex"
      >
        <Link href="/" aria-label="Aegis home" className="mb-5">
          <LogoMark size={34} />
        </Link>
        {NAV.map((item) => (
          <RailLink key={item.href} item={item} pathname={pathname} />
        ))}
        <div className="mt-auto flex flex-col items-center gap-3">
          <Link href="/nodes" aria-label="Node health" className="flex h-8 w-8 items-center justify-center rounded-lg hover:bg-panel-2">
            <NodeStatus compact />
          </Link>
          <RailLink item={SETTINGS} pathname={pathname} />
          <UserMenu name={user.name} email={user.email} role={user.role} version={version} onSignOut={signOut} />
        </div>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-border bg-rail px-4 py-3 md:hidden">
          <Link href="/" aria-label="Aegis home">
            <Wordmark size={26} />
          </Link>
          <div className="flex items-center gap-3">
            <NodeStatus compact />
            <button
              type="button"
              className="btn btn-ghost btn-icon"
              aria-label="Open menu"
              aria-expanded={menu}
              aria-controls="nav-drawer"
              onClick={() => setMenu(true)}
            >
              <Menu size={20} aria-hidden />
            </button>
          </div>
        </header>

        {menu && (
          <div className="fixed inset-0 z-50 md:hidden">
            <button type="button" className="absolute inset-0 bg-black/60" aria-label="Close menu" onClick={() => setMenu(false)} />
            <aside
              id="nav-drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Navigation"
              className="fade-in relative flex h-full w-72 flex-col border-r border-border bg-rail px-4 py-5"
            >
              <div className="mb-6 flex items-center justify-between">
                <Wordmark size={26} sub={version} />
                <button type="button" className="btn btn-ghost btn-icon" aria-label="Close menu" onClick={() => setMenu(false)}>
                  <X size={20} aria-hidden />
                </button>
              </div>
              <div className="flex flex-col gap-1">
                {[...NAV, SETTINGS].map((item) => {
                  const active = isActive(item, pathname);
                  const Icon = item.icon;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      aria-current={active ? "page" : undefined}
                      className={`flex h-11 items-center gap-3 rounded-xl px-3 text-sm font-semibold ${
                        active ? "bg-accent/10 text-accent" : "text-dim hover:bg-panel-2 hover:text-fg"
                      }`}
                    >
                      <Icon size={18} aria-hidden /> {item.label}
                    </Link>
                  );
                })}
              </div>
              <div className="mt-auto space-y-4 border-t border-border pt-4">
                <NodeStatus />
                <div>
                  <div className="text-sm font-semibold">{user.name || user.email}</div>
                  <div className="text-xs text-faint">{user.role}</div>
                </div>
                <ThemeToggle className="btn btn-secondary w-full" />
                <button type="button" className="btn btn-secondary w-full" onClick={signOut}>
                  <LogOut size={16} aria-hidden /> Sign out
                </button>
              </div>
            </aside>
          </div>
        )}

        <main className="min-w-0 flex-1 px-4 py-6 fade-in sm:px-9 sm:py-7">
          {/* One content width for every page; pages do not set their own. */}
          <div className="mx-auto w-full max-w-[1400px]">{children}</div>
        </main>
      </div>
    </div>
  );
}
