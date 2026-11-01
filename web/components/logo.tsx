// The Aegis mark: a shield with an "A" cut through it. Colours come from
// the theme tokens so it follows the palette.
export function LogoMark({ size = 32, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" className={`shrink-0 ${className}`}>
      <path d="M16 2 4 6.5v8.2C4 22 9.2 27.6 16 30c6.8-2.4 12-8 12-15.3V6.5L16 2z" fill="var(--accent)" />
      <path
        d="M10.5 20.5 16 9.5l5.5 11M12.6 16.5h6.8"
        fill="none"
        stroke="var(--ink)"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Wordmark({ size = 28, sub }: { size?: number; sub?: string }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <LogoMark size={size} />
      <span className="font-display text-lg font-semibold tracking-tight">Aegis</span>
      {sub && <span className="font-mono text-xs text-faint">{sub}</span>}
    </span>
  );
}
