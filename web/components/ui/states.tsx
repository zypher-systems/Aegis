import { ReactNode } from "react";
import { Inbox } from "lucide-react";

// Skeleton rows while data loads. Same rhythm as table rows.
export function Loading({ rows = 4, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-label={label} className="mt-4 space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="pulse h-4 rounded-sm bg-panel-2"
          style={{ width: `${[92, 78, 85, 64, 88, 70][i % 6]}%` }}
        />
      ))}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="mt-4 text-sm">
      <p className="text-danger">{message}</p>
      {onRetry && (
        <button type="button" className="btn btn-ghost mt-2" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

// Empty result. `title` for page-level empties, plain `body` for a panel.
export function Empty({ title, body, action }: { title?: string; body: ReactNode; action?: ReactNode }) {
  if (!title) return <p className="mt-4 text-sm text-dim">{body}</p>;
  return (
    <div className="card fade-in flex flex-col items-center px-6 py-14 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-border-strong bg-panel-2 text-dim">
        <Inbox size={22} aria-hidden />
      </div>
      <h3 className="section-title mt-4">{title}</h3>
      <p className="mt-1.5 max-w-sm text-sm text-dim">{body}</p>
      {action ? <div className="mt-6">{action}</div> : null}
    </div>
  );
}
