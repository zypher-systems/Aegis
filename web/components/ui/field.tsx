"use client";

import { ReactElement, ReactNode, cloneElement, isValidElement, useId } from "react";

// Label + control + hint/error. The single child control gets an id so the
// label is associated with it (screen readers, click-to-focus). For a set of
// buttons (radio-style pickers) pass `group`: the label names a role="group".
export function Field({
  label,
  hint,
  error,
  children,
  className = "",
  group = false,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  children: ReactNode;
  className?: string;
  group?: boolean;
}) {
  const auto = useId();
  if (group) {
    return (
      <div className={`space-y-1.5 ${className}`}>
        <div id={`${auto}-label`} className="text-sm text-dim">
          {label}
        </div>
        <div role="group" aria-labelledby={`${auto}-label`} aria-describedby={hint || error ? `${auto}-hint` : undefined}>
          {children}
        </div>
        {error ? (
          <p id={`${auto}-hint`} className="text-xs text-danger">
            {error}
          </p>
        ) : hint ? (
          <p id={`${auto}-hint`} className="text-xs text-faint">
            {hint}
          </p>
        ) : null}
      </div>
    );
  }
  let id = auto;
  let control = children;
  if (isValidElement(children)) {
    const el = children as ReactElement<{ id?: string; "aria-describedby"?: string }>;
    id = el.props.id ?? auto;
    control = cloneElement(el, {
      id,
      "aria-describedby": hint || error ? `${id}-hint` : el.props["aria-describedby"],
    });
  }
  return (
    <div className={`space-y-1.5 ${className}`}>
      {label !== "" && (
        <label htmlFor={id} className="block text-sm text-dim">
          {label}
        </label>
      )}
      {control}
      {error ? (
        <p id={`${id}-hint`} className="text-xs text-danger">
          {error}
        </p>
      ) : hint ? (
        <p id={`${id}-hint`} className="text-xs text-faint">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
