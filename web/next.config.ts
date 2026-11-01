import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  // DNS-01 (Cloudflare + Let's Encrypt) commonly exceeds the 30s rewrite default.
  experimental: {
    proxyTimeout: 5 * 60 * 1000,
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          {
            key: "Content-Security-Policy",
            value: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
          },
        ],
      },
    ];
  },
  async rewrites() {
    // Proxy API calls to the control plane. In the compose stack the api
    // service is reachable as "api:8080"; locally it is localhost:18080.
    const apiBase = process.env.AEGIS_API_INTERNAL ?? "http://api:8080";
    return [{ source: "/api/:path*", destination: `${apiBase}/api/:path*` }];
  },
};

export default nextConfig;
