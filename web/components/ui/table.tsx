"use client";

import { ReactNode, useEffect, useMemo, useState } from "react";
import { fmtInt } from "@/lib/format";

export type Column = { label: ReactNode; align?: "left" | "right"; className?: string };

// A table on a card surface. Scrolls sideways on narrow screens instead of
// breaking the page. `bare` drops the card (tables inside a card already).
export function Table({
  columns,
  children,
  className = "",
  bare = false,
}: {
  columns: Column[];
  children: ReactNode;
  className?: string;
  bare?: boolean;
}) {
  return (
    <div className={`overflow-x-auto ${bare ? "" : "card"} ${className}`}>
      <table className={`data-table w-full min-w-[36rem] text-sm ${bare ? "data-table-bare" : ""}`}>
        <thead>
          <tr className="border-b border-border text-left text-xs font-semibold text-faint">
            {columns.map((c, i) => (
              <th
                key={i}
                scope="col"
                className={`whitespace-nowrap py-3 pr-5 font-semibold last:pr-0 ${c.align === "right" ? "text-right" : ""} ${c.className ?? ""}`}
              >
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

// Client-side paging over an already-loaded list. Resets to page 1 when the
// list shrinks below the current page (filter, delete).
export function usePaged<T>(items: T[], pageSize = 25) {
  const [page, setPage] = useState(1);
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  useEffect(() => {
    if (page > pages) setPage(1);
  }, [page, pages]);
  const pageItems = useMemo(
    () => items.slice((page - 1) * pageSize, page * pageSize),
    [items, page, pageSize],
  );
  return { page, pages, setPage, pageItems, total: items.length, pageSize };
}

// "Showing 1–25 of 140" plus prev/next.
export function Pager({
  page,
  pages,
  setPage,
  total,
  pageSize,
  noun = "rows",
}: {
  page: number;
  pages: number;
  setPage: (p: number) => void;
  total: number;
  pageSize: number;
  noun?: string;
}) {
  if (total === 0) return null;
  const from = (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="mt-3 flex items-center justify-between gap-4 text-xs text-faint">
      <span>
        {pages > 1 ? `${fmtInt(from)}–${fmtInt(to)} of ` : ""}
        {fmtInt(total)} {noun}
      </span>
      {pages > 1 && (
        <div className="flex items-center gap-4">
          <button type="button" className="btn btn-ghost text-xs" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            ← Prev
          </button>
          <span className="tabular-nums">
            {page} / {pages}
          </span>
          <button type="button" className="btn btn-ghost text-xs" disabled={page >= pages} onClick={() => setPage(page + 1)}>
            Next →
          </button>
        </div>
      )}
    </div>
  );
}

// Filter box for lists. Matching is the caller's job.
export function SearchInput({
  value,
  onChange,
  placeholder = "Filter",
  label = "Filter",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  label?: string;
}) {
  return (
    <input
      type="search"
      aria-label={label}
      className="input max-w-xs text-sm"
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}
