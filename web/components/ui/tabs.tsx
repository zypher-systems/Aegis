"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type TabItem<T extends string> = { id: T; label: string; count?: number };

// Underline tabs with arrow-key navigation (WAI-ARIA tabs pattern). Pair
// each panel with <TabPanel id=… active=…>.
export function Tabs<T extends string>({
  items,
  value,
  onChange,
  label,
}: {
  items: TabItem<T>[];
  value: T;
  onChange: (id: T) => void;
  label: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  function onKey(e: React.KeyboardEvent, i: number) {
    let next = -1;
    if (e.key === "ArrowRight") next = (i + 1) % items.length;
    else if (e.key === "ArrowLeft") next = (i - 1 + items.length) % items.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = items.length - 1;
    if (next < 0) return;
    e.preventDefault();
    onChange(items[next].id);
    refs.current[next]?.focus();
  }
  return (
    <div role="tablist" aria-label={label} className="flex gap-6 overflow-x-auto border-b border-border">
      {items.map((t, i) => {
        const active = t.id === value;
        return (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={active}
            aria-controls={`panel-${t.id}`}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(t.id)}
            onKeyDown={(e) => onKey(e, i)}
            className={`-mb-px shrink-0 whitespace-nowrap border-b-2 pb-3 text-sm font-semibold transition-colors ${
              active ? "border-accent text-fg" : "border-transparent text-dim hover:text-fg"
            }`}
          >
            {t.label}
            {t.count !== undefined && <span className="ml-1.5 text-xs text-faint">{t.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({ id, active, children }: { id: string; active: boolean; children: React.ReactNode }) {
  if (!active) return null;
  return (
    <div role="tabpanel" id={`panel-${id}`} aria-labelledby={`tab-${id}`} className="fade-in">
      {children}
    </div>
  );
}

// Keeps the active tab in the URL hash so reloads and links land on it.
export function useHashTab<T extends string>(ids: readonly T[], fallback: T): [T, (id: T) => void] {
  const [tab, setTab] = useState<T>(fallback);
  useEffect(() => {
    const read = () => {
      const h = window.location.hash.slice(1) as T;
      setTab(ids.includes(h) ? h : fallback);
    };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
    // ids is a constant list at every call site, so it is not a dependency.
  }, [fallback]);
  const set = useCallback((id: T) => {
    setTab(id);
    history.replaceState(null, "", `#${id}`);
  }, []);
  return [tab, set];
}
