// k6 smoke — numbers only. No pass/fail latency gate (that is gate.js).
// Hits the pipelined host by default (k6.local after happy-path).
//   k6 run tests/load/smoke.js
//   EDGE_HTTP=http://localhost:80 HOST=k6.local k6 run tests/load/smoke.js

import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 5,
  duration: "20s",
  thresholds: {
    checks: ["rate>0.99"],
  },
};

const BASE = __ENV.EDGE_HTTP || "http://127.0.0.1:80";
const HOST = __ENV.HOST || "k6.local";

export default function () {
  const res = http.get(`${BASE}/`, { headers: { Host: HOST } });
  check(res, {
    "status is 200": (r) => r.status === 200,
  });
  sleep(0.2);
}

export function handleSummary(data) {
  const httpMetrics = data.metrics.http_req_duration;
  const p50 = httpMetrics ? httpMetrics.values["p(50)"] : null;
  const p99 = httpMetrics ? httpMetrics.values["p(99)"] : null;
  console.log(`aegis k6 smoke  host=${HOST}  p50=${p50}ms  p99=${p99}ms  (no latency gate)`);
  return { stdout: JSON.stringify({ host: HOST, p50, p99 }, null, 2) + "\n" };
}
