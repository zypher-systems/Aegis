"use client";

import { useId, useMemo, useState } from "react";
import { Check, ChevronDown, Search, X } from "lucide-react";
import { COUNTRIES, countryName } from "@/lib/countries";

// Multi-select country list: a boxed trigger showing the selection, which
// opens an inline searchable list. Selected countries are removable chips.
export function CountryPicker({
  label,
  hint,
  selected,
  onChange,
  disabled,
  open,
  onToggle,
}: {
  label: string;
  hint?: string;
  selected: string[];
  onChange: (codes: string[]) => void;
  disabled?: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  const [q, setQ] = useState("");
  const id = useId();
  const selectedSet = useMemo(() => new Set(selected), [selected]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return COUNTRIES;
    return COUNTRIES.filter((c) => c.name.toLowerCase().includes(needle) || c.code.toLowerCase().includes(needle));
  }, [q]);
  const expanded = open && !disabled;

  function toggle(code: string) {
    if (selectedSet.has(code)) onChange(selected.filter((c) => c !== code));
    else onChange([...selected, code].sort());
  }

  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm text-dim">
        {label}
      </label>
      <button
        id={id}
        type="button"
        disabled={disabled}
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls={`${id}-list`}
        aria-describedby={hint && !expanded ? `${id}-hint` : undefined}
        className={`flex h-10 w-full items-center gap-2 rounded-control border bg-bg px-3 text-left text-sm transition-colors ${
          expanded ? "border-accent" : "border-border-strong hover:border-border-hover"
        } ${disabled ? "cursor-not-allowed opacity-50" : ""}`}
      >
        <span className={`min-w-0 flex-1 truncate ${selected.length ? "text-fg" : "text-faint"}`}>{summary(selected)}</span>
        {selected.length > 0 && (
          <span className="rounded-md bg-accent/10 px-1.5 font-mono text-[11px] font-bold text-accent">{selected.length}</span>
        )}
        <ChevronDown size={16} aria-hidden className={`shrink-0 text-faint transition-transform ${expanded ? "rotate-180" : ""}`} />
      </button>
      {hint && !expanded && (
        <p id={`${id}-hint`} className="text-xs text-faint">
          {hint}
        </p>
      )}
      {expanded && (
        <div id={`${id}-list`} className="fade-in rounded-control border border-border-strong bg-bg p-2">
          <div className="flex items-center gap-2">
            <div className="relative min-w-0 flex-1">
              <Search size={14} aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
              <input
                className="input h-9 pl-8 text-sm"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search countries"
                aria-label={`Search countries for ${label}`}
                autoFocus
              />
            </div>
            {selected.length > 0 && (
              <button type="button" className="btn btn-ghost btn-sm shrink-0" onClick={() => onChange([])}>
                Clear
              </button>
            )}
          </div>
          {selected.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {selected.map((code) => (
                <button
                  key={code}
                  type="button"
                  onClick={() => toggle(code)}
                  aria-label={`Remove ${countryName(code)}`}
                  className="inline-flex items-center gap-1 rounded-md bg-accent/10 px-2 py-0.5 text-[11px] font-bold text-accent hover:bg-accent/20"
                >
                  {countryName(code)} <X size={12} aria-hidden />
                </button>
              ))}
            </div>
          )}
          <div className="mt-2 max-h-52 overflow-y-auto">
            {filtered.length === 0 && <p className="px-2 py-3 text-sm text-dim">No matches.</p>}
            {filtered.map((c) => {
              const on = selectedSet.has(c.code);
              return (
                <button
                  key={c.code}
                  type="button"
                  onClick={() => toggle(c.code)}
                  aria-pressed={on}
                  className={`flex w-full items-center gap-2.5 rounded-lg px-2 py-1.5 text-left text-sm ${
                    on ? "text-fg" : "text-dim hover:bg-panel-2 hover:text-fg"
                  }`}
                >
                  <span
                    aria-hidden
                    className={`inline-flex h-4 w-4 shrink-0 items-center justify-center rounded border ${
                      on ? "border-accent bg-accent text-ink" : "border-border-strong"
                    }`}
                  >
                    {on && <Check size={12} strokeWidth={3} />}
                  </span>
                  <span className="min-w-0 flex-1 truncate">{c.name}</span>
                  <span className="font-mono text-xs text-faint">{c.code}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function summary(codes: string[]) {
  if (codes.length === 0) return "No countries";
  const names = codes.map(countryName);
  if (names.length <= 2) return names.join(", ");
  return `${names[0]}, ${names[1]} +${names.length - 2}`;
}
