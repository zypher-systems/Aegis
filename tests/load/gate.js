// k6 added-latency gate. Measures proxy → demo minus direct demo.
// From 1.2.0 this hits k6.local, which has the security pipeline compiled
// in (Coraza CRS PL1, rate-limit consult, geo + CrowdSec wraps). Sub-ms
// thresholds were the ungated path; CRS is not free.
//
//   DIRECT=http://demo:80 PROXY=http://proxy:80 HOST=k6.local k6 run tests/load/gate.js

import http from "k6/http";
import { check } from "k6";
import { Trend } from "k6/metrics";

const added = new Trend("added_ms");

export const options = {
  vus: 5,
  duration: "20s",
  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
  thresholds: {
    // Honest CRS PL1 + Redis rate-limit on a CI runner, not plain proxying.
    added_ms: ["p(50)<40", "p(99)<150"],
    checks: ["rate>0.99"],
  },
};

const DIRECT = __ENV.DIRECT || "http://demo:80";
const PROXY = __ENV.PROXY || __ENV.EDGE_HTTP || "http://proxy:80";
const HOST = __ENV.HOST || "k6.local";

export default function () {
  const direct = http.get(`${DIRECT}/`);
  const proxied = http.get(`${PROXY}/`, { headers: { Host: HOST } });
  check(direct, { "direct 200": (r) => r.status === 200 });
  check(proxied, { "proxy 200": (r) => r.status === 200 });
  added.add(proxied.timings.duration - direct.timings.duration);
}

export function handleSummary(data) {
  const m = data.metrics.added_ms;
  const vals = m && m.values ? m.values : {};
  const p50 = vals["p(50)"] ?? vals.med ?? null;
  const p99 = vals["p(99)"] ?? null;
  console.log(`aegis k6 gate  host=${HOST}  added p50=${p50}ms  p99=${p99}ms  (fail if p50>=40 or p99>=150)`);
  return { stdout: JSON.stringify({ host: HOST, added_p50: p50, added_p99: p99 }, null, 2) + "\n" };
}
