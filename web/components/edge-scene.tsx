/** Orthogonal schematic of clients → Aegis edge → upstreams, with a config push. */
export function EdgeScene() {
  return (
    <svg className="edge-scene" viewBox="0 0 640 360" role="img" aria-label="Aegis routes traffic through the edge">
      <title>Clients connect through the Aegis edge to upstreams; the control plane pushes config</title>

      <text className="label" x="8" y="28">CLIENTS</text>
      <text className="label" x="286" y="28">CONTROL</text>
      <text className="label" x="286" y="348">EDGE</text>
      <text className="label" x="534" y="28">UPSTREAM</text>

      <circle className="node" cx="28" cy="92" r="3.5" />
      <circle className="node" cx="28" cy="180" r="3.5" />
      <circle className="node" cx="28" cy="268" r="3.5" />

      <path className="wire" id="in-a" d="M36 92 H160 V154 H292" />
      <path className="wire" id="in-b" d="M36 180 H292" />
      <path className="wire" id="in-c" d="M36 268 H160 V206 H292" />

      <rect className="box" x="292" y="118" width="56" height="124" />
      <line className="stage" x1="304" y1="148" x2="336" y2="148" />
      <line className="stage" x1="304" y1="180" x2="336" y2="180" />
      <line className="stage" x1="304" y1="212" x2="336" y2="212" />

      <rect className="box" x="292" y="36" width="56" height="28" />
      <path className="wire wire-dash" d="M320 64 V118" />
      <path className="cfg-pulse" d="M320 64 V118" />

      <path className="wire" id="out-a" d="M348 154 H480 V92 H548" />
      <path className="wire" id="out-b" d="M348 180 H548" />
      <path className="wire" id="out-c" d="M348 206 H480 V268 H548" />

      <rect className="box" x="548" y="78" width="72" height="28" />
      <rect className="box" x="548" y="166" width="72" height="28" />
      <rect className="box" x="548" y="254" width="72" height="28" />

      <circle className="pkt" r="2.5" opacity="0">
        <set attributeName="opacity" to="1" begin="0s" />
        <animateMotion dur="3.4s" repeatCount="indefinite" begin="0s">
          <mpath href="#in-a" />
        </animateMotion>
      </circle>
      <circle className="pkt" r="2.5" opacity="0">
        <set attributeName="opacity" to="1" begin="0.6s" />
        <animateMotion dur="3.8s" repeatCount="indefinite" begin="0.6s">
          <mpath href="#in-b" />
        </animateMotion>
      </circle>
      <circle className="pkt" r="2.5" opacity="0">
        <set attributeName="opacity" to="1" begin="1.2s" />
        <animateMotion dur="3.6s" repeatCount="indefinite" begin="1.2s">
          <mpath href="#in-c" />
        </animateMotion>
      </circle>
      <circle className="pkt" r="2.5" opacity="0">
        <set attributeName="opacity" to="1" begin="1.7s" />
        <animateMotion dur="3.2s" repeatCount="indefinite" begin="1.7s">
          <mpath href="#out-a" />
        </animateMotion>
      </circle>
      <circle className="pkt" r="2.5" opacity="0">
        <set attributeName="opacity" to="1" begin="2.1s" />
        <animateMotion dur="3.5s" repeatCount="indefinite" begin="2.1s">
          <mpath href="#out-b" />
        </animateMotion>
      </circle>
      <circle className="pkt" r="2.5" opacity="0">
        <set attributeName="opacity" to="1" begin="2.6s" />
        <animateMotion dur="3.3s" repeatCount="indefinite" begin="2.6s">
          <mpath href="#out-c" />
        </animateMotion>
      </circle>
    </svg>
  );
}
