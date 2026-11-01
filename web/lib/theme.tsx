"use client";

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { THEME_KEY } from "@/lib/theme-init";

export type Theme = "dark" | "light";

type ThemeCtx = { theme: Theme; toggle: () => void };

const Ctx = createContext<ThemeCtx>({ theme: "dark", toggle: () => undefined });

function apply(theme: Theme) {
  const c = document.documentElement.classList;
  c.toggle("light", theme === "light");
  c.toggle("dark", theme === "dark");
}

// Dark is the default theme and light is the alternate. The choice is stored
// per browser; the OS setting is not consulted, so a fresh install is dark.
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>("dark");

  // The init script in <head> has already set the class; mirror it into state.
  useEffect(() => {
    setTheme(document.documentElement.classList.contains("light") ? "light" : "dark");
  }, []);

  const toggle = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    apply(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // Storage blocked: the choice lasts for this page only.
    }
    setTheme(next);
  }, [theme]);

  return <Ctx.Provider value={{ theme, toggle }}>{children}</Ctx.Provider>;
}

export function useTheme() {
  return useContext(Ctx);
}
