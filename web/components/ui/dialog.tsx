"use client";

import { ReactNode, useEffect, useId, useRef } from "react";

const SIZES = {
  sm: "max-w-md",
  md: "max-w-xl",
  lg: "max-w-3xl",
} as const;

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

// Modal dialog: overlay click and Escape close it, Tab stays inside, focus
// returns to the opener, and the panel scrolls inside the viewport on phones.
// Nest one dialog inside another with layer={1}.
export function Dialog({
  title,
  description,
  onClose,
  size = "md",
  layer = 0,
  footer,
  busy = false,
  confirmClose,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  onClose: () => void;
  size?: keyof typeof SIZES;
  layer?: number;
  footer?: ReactNode;
  // While busy (saving), Escape and backdrop clicks are ignored.
  busy?: boolean;
  // When set, Escape and backdrop clicks ask this question first (unsaved
  // edits); the explicit Cancel button never asks.
  confirmClose?: string;
  children?: ReactNode;
}) {
  const panel = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descId = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const guardRef = useRef({ busy, confirmClose });
  guardRef.current = { busy, confirmClose };
  const tryClose = () => {
    const g = guardRef.current;
    if (g.busy) return;
    if (g.confirmClose && !window.confirm(g.confirmClose)) return;
    closeRef.current();
  };

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    const el = panel.current;
    // Focus the first field unless something inside already asked for it.
    if (el && !el.contains(document.activeElement)) {
      const first = el.querySelector<HTMLElement>("input, select, textarea") ?? el;
      first.focus();
    }
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    function onKey(e: KeyboardEvent) {
      if (!el) return;
      // Only the top-most dialog reacts.
      const dialogs = document.querySelectorAll("[data-dialog]");
      if (dialogs[dialogs.length - 1] !== el) return;
      if (e.key === "Escape") {
        e.stopPropagation();
        tryClose();
        return;
      }
      if (e.key !== "Tab") return;
      const items = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (n) => n.offsetParent !== null,
      );
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (layer === 0) document.body.style.overflow = prevOverflow;
      opener?.focus?.();
    };
  }, [layer]);

  return (
    <div
      className="fixed inset-0 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      style={{ zIndex: 50 + layer * 10 }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) tryClose();
      }}
    >
      <div
        ref={panel}
        data-dialog
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        tabIndex={-1}
        className={`panel fade-in flex max-h-[calc(100dvh-2rem)] w-full flex-col shadow-2xl outline-none ${SIZES[size]}`}
      >
        <div className="px-4 pt-4 sm:px-6 sm:pt-6">
          <h2 id={titleId} className="section-title text-xl">
            {title}
          </h2>
          {description && (
            <p id={descId} className="mt-0.5 text-sm text-dim">
              {description}
            </p>
          )}
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-4 pb-4 pt-4 sm:px-6 sm:pb-6">{children}</div>
        {footer && (
          <div className="flex items-center justify-end gap-2.5 border-t border-border px-4 py-3 sm:px-6">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
