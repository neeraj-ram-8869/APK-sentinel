"use client";
// ===================================================================
// Session 5 — RiskGauge Component
// Animated SVG circular gauge extracted from page.tsx.
// ===================================================================

interface RiskGaugeProps {
  score: number;
  verdict: string;
  confidence?: string;
  size?: number;
}

function verdictColor(score: number): string {
  if (score > 70) return "var(--accent-red)";
  if (score > 30) return "var(--accent-orange)";
  return "var(--accent-green)";
}

export default function RiskGauge({ score, verdict, confidence, size = 150 }: RiskGaugeProps) {
  const r       = 44;
  const circ    = 2 * Math.PI * r;
  const offset  = circ - (circ * score) / 100;
  const color   = verdictColor(score);

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "8px" }}>
      <div style={{ position: "relative", width: size, height: size }}>
        <svg
          viewBox="0 0 100 100"
          style={{ width: "100%", height: "100%", transform: "rotate(-90deg)" }}
        >
          {/* Background track */}
          <circle cx="50" cy="50" r={r} fill="none" stroke="#f1f5f9" strokeWidth="5" />
          {/* Score arc */}
          <circle
            cx="50" cy="50" r={r}
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 1s ease, stroke 0.5s ease" }}
          />
        </svg>

        {/* Center text */}
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, bottom: 0,
          display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        }}>
          <span style={{
            fontSize: `${Math.round(size * 0.155)}px`, fontWeight: 900,
            fontFamily: "var(--font-display)", color: "#0f172a", lineHeight: 1,
          }}>
            {score}
          </span>
          <span style={{ fontSize: `${Math.round(size * 0.053)}px`, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
            / 100
          </span>
        </div>
      </div>

      {/* Verdict + confidence */}
      <div style={{ textAlign: "center" }}>
        <div className="mono" style={{ color, fontWeight: 900, fontSize: "0.95rem", textTransform: "uppercase" }}>
          {verdict}
        </div>
        {confidence && (
          <p style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "2px" }}>
            Confidence: {confidence}
          </p>
        )}
      </div>
    </div>
  );
}
