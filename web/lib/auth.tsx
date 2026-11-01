"use client";

import { createContext, useContext, useEffect, useRef, useState, ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { api, setUnauthorizedHandler } from "./api";
import type { User } from "./types";

type AuthState = {
  user: User | null;
  loading: boolean;
  needsSetup: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthState>({
  user: null,
  loading: true,
  needsSetup: false,
  refresh: async () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [loading, setLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();
  const userRef = useRef(user);
  userRef.current = user;

  useEffect(() => {
    setUnauthorizedHandler(() => {
      const wasAuthed = userRef.current != null;
      setUser(null);
      // Clear a session that just expired. A visitor who was never signed in
      // has no session to clear (and the call would only 403 on CSRF).
      if (wasAuthed) void api.logout().catch(() => {});
      if (pathname === "/login" || pathname === "/setup") return;
      if (wasAuthed && typeof sessionStorage !== "undefined") {
        sessionStorage.setItem("aegis_session_expired", "1");
      }
      const here = window.location.pathname + window.location.search + window.location.hash;
      router.replace(here && here !== "/" ? `/login?next=${encodeURIComponent(here)}` : "/login");
    });
    return () => setUnauthorizedHandler(null);
  }, [pathname, router]);

  async function refresh() {
    try {
      const s = await api.setupStatus();
      setNeedsSetup(s.needs_setup);
      if (!s.needs_setup) {
        try {
          setUser(await api.me());
        } catch {
          setUser(null);
        }
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function logout() {
    try {
      await api.logout();
    } finally {
      setUser(null);
    }
  }

  return (
    <Ctx.Provider value={{ user, loading, needsSetup, refresh, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export const useAuth = () => useContext(Ctx);
