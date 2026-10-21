import { ReactNode } from "react";

// Title row for every page: title, one-line description, actions on the right.
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="min-w-0">
        <h1 className="page-title">{title}</h1>
        {description && <p className="mt-1.5 max-w-3xl text-sm text-dim">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
}

// A titled block inside a page. `card` puts it on a surface (dashboards);
// `divided` draws the top rule used between Settings-style sections;
// otherwise sections are spaced only.
export function Section({
  title,
  description,
  actions,
  divided,
  card,
  className = "",
  children,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  divided?: boolean;
  card?: boolean;
  className?: string;
  children?: ReactNode;
}) {
  return (
    <section className={`${divided ? "section" : card ? "card card-pad" : "mt-10"} ${className}`}>
      {(title || actions) && (
        <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-2">
          <div className="min-w-0">
            {title && <h2 className="section-title">{title}</h2>}
            {description && <p className="mt-1 max-w-3xl text-xs text-faint">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-3 text-sm">{actions}</div>}
        </div>
      )}
      <div className={title || actions ? "mt-4" : ""}>{children}</div>
    </section>
  );
}
