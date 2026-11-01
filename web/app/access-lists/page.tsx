"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { KeyRound, Plus, ShieldBan, ShieldCheck, UserRound, X } from "lucide-react";
import { api, isUnauthorized } from "@/lib/api";
import type { AccessList, AccessListInput, Host } from "@/lib/types";
import { AppShell } from "@/components/app-shell";
import {
  ActionMenu,
  Dialog,
  Empty,
  ErrorState,
  Field,
  Loading,
  PageHeader,
  Pager,
  SearchInput,
  StatusPill,
  usePaged,
} from "@/components/ui";
import { fmtInt } from "@/lib/format";

export default function AccessListsPage() {
  const [lists, setLists] = useState<AccessList[] | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<AccessList | null>(null);
  const [q, setQ] = useState("");

  async function load() {
    try {
      const [l, h] = await Promise.all([api.accessLists(), api.hosts().catch(() => [] as Host[])]);
      setLists(l);
      setHosts(h);
      setErr(null);
    } catch (e) {
      if (isUnauthorized(e)) return;
      setErr(e instanceof Error ? e.message : "Failed to load access lists");
    }
  }

  useEffect(() => { load(); }, []);

  async function onDelete(a: AccessList) {
    if (!confirm(`Delete access list “${a.name}”? Hosts using it will have no list.`)) return;
    try {
      await api.deleteAccessList(a.id);
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Delete failed");
    }
  }

  const usedBy = useMemo(() => {
    const by: Record<string, Host[]> = {};
    for (const h of hosts) if (h.access_list_id) (by[h.access_list_id] ??= []).push(h);
    return by;
  }, [hosts]);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!lists || !needle) return lists ?? [];
    return lists.filter((a) =>
      [a.name, ...(a.users ?? []).map((u) => u.username), ...(a.allow_cidrs ?? []), ...(a.deny_cidrs ?? [])]
        .join(" ")
        .toLowerCase()
        .includes(needle),
    );
  }, [lists, q]);
  const paged = usePaged(filtered, 24);

  function openNew() {
    setEditing(null);
    setOpen(true);
  }
  function openEdit(a: AccessList) {
    setEditing(a);
    setOpen(true);
  }

  return (
    <AppShell>
      <PageHeader
        title="Access lists"
        description="Basic-auth users and IP allow/deny rules. Attach a list to any host."
        actions={
          <button type="button" className="btn btn-primary" onClick={openNew}>
            <Plus size={16} strokeWidth={2.4} aria-hidden /> Add list
          </button>
        }
      />

      {err && (
        <div className="mt-4">
          <ErrorState message={err} onRetry={load} />
        </div>
      )}

      {lists === null ? (
        <div className="card card-pad mt-6">
          <Loading rows={5} label="Loading access lists" />
        </div>
      ) : lists.length === 0 ? (
        <div className="mt-6">
          <Empty
            title="No access lists yet"
            body="Add basic auth users and IP allow/deny, then attach the list on a host."
            action={
              <button type="button" className="btn btn-primary" onClick={openNew}>
                <Plus size={16} strokeWidth={2.4} aria-hidden /> Add list
              </button>
            }
          />
        </div>
      ) : (
        <>
          <div className="mt-6 flex justify-end">
            <div className="w-full sm:w-72">
              <SearchInput value={q} onChange={setQ} placeholder="Filter by name, user, CIDR" label="Filter access lists" />
            </div>
          </div>
          <div className="mt-5">
            {filtered.length === 0 ? (
              <Empty body="No access lists match that filter." />
            ) : (
              <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
                {paged.pageItems.map((a) => (
                  <ListCard
                    key={a.id}
                    a={a}
                    hosts={usedBy[a.id] ?? []}
                    onEdit={() => openEdit(a)}
                    onDelete={() => onDelete(a)}
                  />
                ))}
              </div>
            )}
            <Pager {...paged} noun={filtered.length === 1 ? "list" : "lists"} />
          </div>
        </>
      )}

      {open && (
        <AccessListDialog
          list={editing}
          onClose={() => setOpen(false)}
          onSaved={async () => { setOpen(false); await load(); }}
        />
      )}
    </AppShell>
  );
}

function ListCard({ a, hosts, onEdit, onDelete }: { a: AccessList; hosts: Host[]; onEdit: () => void; onDelete: () => void }) {
  const users = a.users ?? [];
  const allow = a.allow_cidrs ?? [];
  const deny = a.deny_cidrs ?? [];
  return (
    <article className="card flex flex-col gap-4 p-5 transition-colors hover:border-border-strong">
      <div className="flex items-start gap-3">
        <div
          aria-hidden
          className="flex h-10 w-10 shrink-0 items-center justify-center rounded-[11px] border border-border-strong bg-panel-2 text-dim"
        >
          <KeyRound size={18} />
        </div>
        <div className="min-w-0 flex-1">
          <button type="button" onClick={onEdit} className="block max-w-full truncate text-left font-display text-base font-semibold hover:text-accent">
            {a.name}
          </button>
          <div className="mt-0.5 text-xs text-faint">
            {hosts.length === 0 ? "Not attached to a host" : `Used by ${fmtInt(hosts.length)} ${hosts.length === 1 ? "host" : "hosts"}`}
          </div>
        </div>
        <StatusPill tone={a.satisfy === "any" ? "accent" : "neutral"}>{a.satisfy === "any" ? "Match any" : "Match all"}</StatusPill>
        <ActionMenu
          label={`Actions for ${a.name}`}
          items={[
            { label: "Edit list", onSelect: onEdit },
            { label: "Delete list", danger: true, onSelect: onDelete },
          ]}
        />
      </div>

      <dl className="grid grid-cols-3 gap-3 border-y border-border py-3.5">
        <Stat icon={<UserRound size={14} aria-hidden />} label="Users" value={users.length} />
        <Stat icon={<ShieldCheck size={14} aria-hidden className="text-ok" />} label="Allow" value={allow.length} />
        <Stat icon={<ShieldBan size={14} aria-hidden className="text-danger" />} label="Deny" value={deny.length} />
      </dl>

      <div className="flex min-h-[22px] flex-wrap gap-1.5">
        {users.slice(0, 4).map((u) => (
          <span key={u.username} className="rounded-md bg-panel-2 px-2 py-0.5 font-mono text-[11px] text-dim">
            {u.username}
          </span>
        ))}
        {[...allow.map((c) => ({ c, allow: true })), ...deny.map((c) => ({ c, allow: false }))].slice(0, 4).map(({ c, allow: ok }) => (
          <span
            key={`${ok ? "a" : "d"}-${c}`}
            className={`rounded-md px-2 py-0.5 font-mono text-[11px] ${ok ? "bg-ok/10 text-ok" : "bg-danger/10 text-danger"}`}
          >
            {ok ? "allow" : "deny"} {c}
          </span>
        ))}
        {users.length === 0 && allow.length === 0 && deny.length === 0 && (
          <span className="text-xs text-faint">Empty list: every request passes.</span>
        )}
      </div>

      {hosts.length > 0 && (
        <div className="truncate text-xs text-faint" title={hosts.map((h) => h.domain_names[0]).join(", ")}>
          {hosts.map((h) => h.domain_names[0]).join(", ")}
        </div>
      )}
    </article>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div>
      <dt className="flex items-center gap-1.5 text-xs text-faint">
        {icon}
        {label}
      </dt>
      <dd className="display-num mt-0.5 text-xl">{fmtInt(value)}</dd>
    </div>
  );
}

function AccessListDialog({
  list,
  onClose,
  onSaved,
}: {
  list: AccessList | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = list !== null;
  const [name, setName] = useState(list?.name ?? "");
  const [satisfy, setSatisfy] = useState<"any" | "all">(list?.satisfy ?? "all");
  // Existing users come back without passwords; an empty password on save
  // keeps the stored hash.
  const [users, setUsers] = useState<{ username: string; password: string }[]>(
    (list?.users ?? []).map((u) => ({ username: u.username, password: "" })),
  );
  const [allow, setAllow] = useState((list?.allow_cidrs ?? []).join("\n"));
  const [deny, setDeny] = useState((list?.deny_cidrs ?? []).join("\n"));
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    const userRows = users
      .map((u) => ({ username: u.username.trim(), password: u.password }))
      .filter((u) => u.username);
    const payload: AccessListInput = {
      name,
      satisfy,
      users: userRows,
      allow_cidrs: allow.split("\n").map((s) => s.trim()).filter(Boolean),
      deny_cidrs: deny.split("\n").map((s) => s.trim()).filter(Boolean),
    };
    setBusy(true);
    try {
      if (isEdit) await api.updateAccessList(list.id, payload);
      else await api.createAccessList(payload);
      onSaved();
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Save failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={isEdit ? "Edit access list" : "Add access list"}
      description="Users get HTTP basic auth. CIDRs are checked against the client address."
      size="lg"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button type="submit" form="access-list-form" className="btn btn-primary" disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </button>
        </>
      }
    >
      <form id="access-list-form" onSubmit={onSubmit} className="space-y-4">
        {err && <p role="alert" className="text-sm text-danger">{err}</p>}
        <Field label="Name">
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label="Satisfy">
          <select className="input max-w-sm" value={satisfy} onChange={(e) => setSatisfy(e.target.value as "any" | "all")}>
            <option value="all">all (IP and auth)</option>
            <option value="any">any (IP or auth)</option>
          </select>
        </Field>
        <fieldset className="space-y-2">
          <legend className="text-sm text-dim">Users</legend>
          <p className="text-xs text-faint">Leave a password empty on edit to keep the stored one.</p>
          {users.length === 0 && <p className="text-sm text-faint">No users. Requests are checked by IP rules only.</p>}
          {users.map((u, i) => (
            <div key={i} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] gap-2">
              <input
                className="input mono"
                aria-label={`Username ${i + 1}`}
                placeholder="username"
                autoComplete="off"
                value={u.username}
                onChange={(e) => setUsers((cur) => cur.map((x, j) => (j === i ? { ...x, username: e.target.value } : x)))}
              />
              <input
                className="input mono"
                type="password"
                aria-label={`Password for user ${i + 1}`}
                placeholder={isEdit && list?.users?.some((x) => x.username === u.username) ? "unchanged" : "password"}
                autoComplete="new-password"
                value={u.password}
                onChange={(e) => setUsers((cur) => cur.map((x, j) => (j === i ? { ...x, password: e.target.value } : x)))}
              />
              <button
                type="button"
                className="btn btn-ghost btn-icon h-10"
                aria-label={`Remove user ${u.username || i + 1}`}
                onClick={() => setUsers((cur) => cur.filter((_, j) => j !== i))}
              >
                <X size={16} aria-hidden />
              </button>
            </div>
          ))}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setUsers((cur) => [...cur, { username: "", password: "" }])}
          >
            <Plus size={14} strokeWidth={2.4} aria-hidden /> Add user
          </button>
        </fieldset>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Allow CIDRs" hint="One per line.">
            <textarea className="input mono min-h-28" value={allow} onChange={(e) => setAllow(e.target.value)} placeholder="10.0.0.0/8" />
          </Field>
          <Field label="Deny CIDRs" hint="One per line.">
            <textarea className="input mono min-h-28" value={deny} onChange={(e) => setDeny(e.target.value)} placeholder="192.168.1.50" />
          </Field>
        </div>
      </form>
    </Dialog>
  );
}
