"use client";

// ===================================================================
// Session 5 — ScoreBreakdown Component
// Expandable cards showing each contribution to the risk score.
// ===================================================================

import { useState } from "react";
import type { ScoringResult, ScoreContribution } from "@/lib/scoring/engine";

interface ScoreBreakdownProps {
  result: ScoringResult;
}

const CATEGORY_ICONS: Record<ScoreContribution["category"], string> = {
  Permission:  "🔐",
  Certificate: "🔏",
  Network:     "🌐",
  SDK:         "📦",
  Manifest:    "📄",
  Finding:     "🔍",
};

const SEVERITY_COLORS: Record<ScoreContribution["severity"], string> = {
  CRITICAL: "var(--accent-red)",
  HIGH:     "#e05c00",
  MEDIUM:   "var(--accent-yellow)",
  LOW:      "var(--accent-green)",
};

const SEVERITY_BG: Record<ScoreContribution["severity"], string> = {
  CRITICAL: "rgba(220,38,38,0.07)",
  HIGH:     "rgba(234,88,12,0.07)",
  MEDIUM:   "rgba(217,119,6,0.07)",
  LOW:      "rgba(5,150,105,0.07)",
};

export default function ScoreBreakdown({ result }: ScoreBreakdownProps) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  const visible = showAll ? result.contributions : result.contributions.slice(0, 6);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h5 style={{
          fontSize: "0.75rem", fontWeight: 800, color: "var(--text-muted)",
          textTransform: "uppercase", letterSpacing: "0.05em"
        }}>
          Score Breakdown ({result.contributions.length} factors)
        </h5>
        <span className="mono" style={{
          fontSize: "0.7rem", color: "var(--text-muted)",
          background: "var(--bg-card-hover)", padding: "2px 8px", borderRadius: "4px",
          border: "1px solid var(--border-color)"
        }}>
          {result.score}/100
        </span>
      </div>

      {/* Top risk summary */}
      <div style={{
        background: "rgba(99, 102, 241, 0.04)",
        border: "1px solid rgba(99, 102, 241, 0.12)",
        borderLeft: "3px solid var(--accent-purple)",
        borderRadius: "0 6px 6px 0",
        padding: "10px 14px",
        fontSize: "0.78rem",
        color: "var(--text-secondary)",
      }}>
        {result.topRisk}
      </div>

      {/* Contribution cards */}
      {visible.map((contrib) => {
        const isOpen = expanded === contrib.id;
        return (
          <div
            key={contrib.id}
            style={{
              border: "1px solid var(--border-color)",
              borderRadius: "6px",
              overflow: "hidden",
              background: isOpen ? SEVERITY_BG[contrib.severity] : "var(--bg-card)",
              transition: "background 0.15s",
            }}
          >
            {/* Row header */}
            <div
              onClick={() => setExpanded(isOpen ? null : contrib.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                padding: "10px 14px",
                cursor: "pointer",
              }}
            >
              {/* Icon */}
              <span style={{ fontSize: "0.85rem" }}>{CATEGORY_ICONS[contrib.category]}</span>

              {/* Label */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: "0.78rem", fontWeight: 700, color: "var(--text-primary)",
                  whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
                }}>
                  {contrib.label}
                </div>
                <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginTop: "1px" }}>
                  {contrib.category}
                </div>
              </div>

              {/* Weight badge */}
              <span style={{
                background: SEVERITY_BG[contrib.severity],
                color: SEVERITY_COLORS[contrib.severity],
                border: `1px solid ${SEVERITY_COLORS[contrib.severity]}30`,
                borderRadius: "4px",
                padding: "2px 8px",
                fontSize: "0.68rem",
                fontWeight: 800,
                fontFamily: "var(--font-mono)",
                whiteSpace: "nowrap",
              }}>
                +{contrib.weight}
              </span>

              {/* Chevron */}
              <span style={{
                fontSize: "0.7rem", color: "var(--text-muted)",
                transform: isOpen ? "rotate(180deg)" : "none",
                transition: "transform 0.15s",
              }}>▾</span>
            </div>

            {/* Expanded evidence */}
            {isOpen && (
              <div style={{
                borderTop: "1px solid var(--border-color)",
                padding: "10px 14px",
                background: SEVERITY_BG[contrib.severity],
              }}>
                <div style={{ fontSize: "0.72rem", color: "var(--text-secondary)", lineHeight: 1.5 }}>
                  <span style={{ fontWeight: 700, color: "var(--text-primary)" }}>Evidence: </span>
                  <span className="mono">{contrib.evidence}</span>
                </div>
                <div style={{ fontSize: "0.72rem", color: "var(--text-secondary)", marginTop: "4px" }}>
                  <span style={{ fontWeight: 700, color: "var(--text-primary)" }}>Severity: </span>
                  <span style={{ color: SEVERITY_COLORS[contrib.severity], fontWeight: 700 }}>
                    {contrib.severity}
                  </span>
                  <span style={{ color: "var(--text-muted)", marginLeft: "8px" }}>
                    Contributes {contrib.weight} of {result.score} total points
                    ({Math.round((contrib.weight / result.score) * 100)}%)
                  </span>
                </div>
              </div>
            )}
          </div>
        );
      })}

      {/* Show more / less */}
      {result.contributions.length > 6 && (
        <button
          onClick={() => setShowAll(!showAll)}
          style={{
            background: "transparent",
            border: "1px dashed var(--border-color)",
            borderRadius: "6px",
            color: "var(--accent-purple)",
            fontWeight: 700,
            fontSize: "0.75rem",
            padding: "8px",
            cursor: "pointer",
          }}
        >
          {showAll
            ? "Show fewer factors"
            : `Show ${result.contributions.length - 6} more factors`}
        </button>
      )}
    </div>
  );
}
