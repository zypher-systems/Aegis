import type { Config } from "tailwindcss";

// Tailwind can only apply opacity modifiers (bg-danger/10) to colours it can
// decompose, so tokens are rgb() over the channel vars in globals.css.
const rgb = (name: string) => `rgb(var(--${name}-rgb) / <alpha-value>)`;

const config: Config = {
  darkMode: "class",
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ["var(--font-display)"],
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
      borderRadius: {
        card: "var(--radius-card)",
        control: "var(--radius-control)",
      },
      colors: {
        bg: {
          DEFAULT: rgb("bg"),
          elev: rgb("bg-elev"),
        },
        panel: {
          DEFAULT: rgb("panel"),
          2: rgb("panel-2"),
        },
        border: {
          DEFAULT: rgb("border"),
          strong: rgb("border-strong"),
          hover: rgb("border-hover"),
        },
        rail: rgb("rail"),
        ink: rgb("ink"),
        fg: rgb("text"),
        dim: rgb("text-dim"),
        faint: rgb("text-faint"),
        accent: rgb("accent"),
        ok: rgb("ok"),
        warn: rgb("warn"),
        danger: rgb("danger"),
      },
    },
  },
  plugins: [],
};
export default config;
