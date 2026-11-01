import type { Metadata } from "next";
// Fonts are bundled from npm (@fontsource) so builds and air-gapped
// installs never fetch from a font CDN.
import "@fontsource-variable/space-grotesk";
import "@fontsource-variable/manrope";
import "@fontsource-variable/jetbrains-mono";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { ThemeProvider } from "@/lib/theme";
import { THEME_INIT } from "@/lib/theme-init";

export const metadata: Metadata = {
  title: "Aegis",
  description: "Aegis: security-first edge proxy",
  icons: { icon: "/favicon.svg" },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    // The init script may swap the class before hydration, hence the suppress.
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
      </head>
      <body className="aegis-backdrop">
        <ThemeProvider>
          <AuthProvider>{children}</AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
