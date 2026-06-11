"use client";
// ===================================================================
// Session 4 — AiSummaryCard Component
// Compact card shown at top of dashboard with NIM-generated one-liner.
// ===================================================================

interface AiSummaryCardProps {
  isLoading: boolean;
  verdict: string;
  score: number;
  topRisk: string;
  packageName: string;
  source?: "nim" | "fallback";
}

const VERDICT_CONFIG = {
  MALICIOUS:  { color: "var(--accent-red)",    bg: "rgba(220,38,38,0.06)",  icon: "🔴" },
  FRAUDULENT: { color: "var(--accent-orange)",  bg: "rgba(234,88,12,0.06)",  icon: "🟠" },
  SUSPICIOUS: { color: "var(--accent-yellow)",  bg: "rgba(217,119,6,0.06)",  icon: "🟡" },
  BENIGN:     { color: "var(--accent-green)",   bg: "rgba(5,150,105,0.06)",  icon: "🟢" },
};

export default function AiSummaryCard({
  isLoading, verdict, score, topRisk, packageName, source = "fallback",
}: AiSummaryCardProps) {
  const cfg = VERDICT_CONFIG[verdict as keyof typeof VERDICT_CONFIG] ?? VERDICT_CONFIG.BENIGN;

  return (
    <div style={{
      background: cfg.bg,
      border: `1px solid ${cfg.color}30`,
      borderLeft: `3px solid ${cfg.color}`,
      borderRadius: "0 6px 6px 0",
      padding: "12px 16px",
      display: "flex",
      alignItems: "center",
      gap: "12px",
      flexWrap: "wrap",
    }}>
      {/* Icon + verdict */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
        <span style={{ fontSize: "1.1rem" }}>{cfg.icon}</span>
        <div>
          <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", fontWeight: 700, textTransform: "uppercase" }}>
            AI Verdict
          </div>
          <div style={{ fontSize: "0.85rem", fontWeight: 900, color: cfg.color }}>
            {verdict} — {score}/100
          </div>
        </div>
      </div>

      {/* Divider */}
      <div style={{ width: "1px", height: "32px", background: `${cfg.color}30`, flexShrink: 0 }} />

      {/* Top risk summary */}
      <div style={{ flex: 1, minWidth: "180px" }}>
        {isLoading ? (
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <div style={{
              width: "12px", height: "12px", borderRadius: "50%",
              border: "2px solid var(--accent-purple)",
              borderTopColor: "transparent",
              animation: "spin 0.8s linear infinite",
              flexShrink: 0,
            }} />
            <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>
              Generating AI analysis…
            </span>
          </div>
        ) : (
          <div style={{ fontSize: "0.78rem", color: "var(--text-secondary)", lineHeight: 1.4 }}>
            {topRisk}
          </div>
        )}
      </div>

      {/* Source badge */}
      <span style={{
        fontSize: "0.62rem", fontWeight: 800, fontFamily: "var(--font-mono)",
        padding: "2px 7px", borderRadius: "3px", flexShrink: 0,
        background: source === "nim" ? "rgba(99,102,241,0.08)" : "rgba(148,163,184,0.08)",
        color: source === "nim" ? "var(--accent-purple)" : "var(--text-muted)",
        border: `1px solid ${source === "nim" ? "rgba(99,102,241,0.2)" : "var(--border-subtle)"}`,
      }}>
        {source === "nim" ? "⚡ NIM" : "STATIC"}
      </span>
    </div>
  );
}
