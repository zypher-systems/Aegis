"use client";

import { ReactNode, useId } from "react";

// On/off control. role="switch" with aria-checked; the whole row is the hit
// target. `locked` explains why it cannot be turned on. A locked switch that
// is already on can still be turned off.
export function Switch({
  label,
  description,
  checked,
  onChange,
  disabled,
  locked,
}: {
  label: ReactNode;
  description?: ReactNode;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  locked?: ReactNode;
}) {
  const id = useId();
  const off = disabled || (!!locked && !checked);
  return (
    <div className="py-2">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-describedby={description || locked ? `${id}-d` : undefined}
        disabled={off}
        onClick={() => onChange(!checked)}
        className="group flex w-full items-center justify-between gap-4 text-left text-sm disabled:cursor-not-allowed"
      >
        <span className={off ? "text-faint" : checked ? "text-fg" : "text-dim group-hover:text-fg"}>{label}</span>
        <span
          aria-hidden
          className={`relative inline-flex h-4 w-7 shrink-0 items-center rounded-full border transition-colors ${
            checked ? "border-accent/60 bg-accent/25" : "border-border-strong bg-transparent"
          } ${off ? "opacity-50" : ""}`}
        >
          <span
            className={`absolute h-2.5 w-2.5 rounded-full transition-transform ${
              checked ? "translate-x-[14px] bg-accent" : "translate-x-[2px] bg-faint"
            }`}
          />
        </span>
      </button>
      {(locked || description) && (
        <div id={`${id}-d`} className="mt-0.5 space-y-0.5 text-xs">
          {description && <p className="text-faint">{description}</p>}
          {locked && <p className="text-warn">{locked}</p>}
        </div>
      )}
    </div>
  );
}
