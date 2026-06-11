"use client";

// ===================================================================
// Session 5 — AnalysisTimeline Component
// Animated vertical timeline of analysis pipeline stages.
// ===================================================================

import { useEffect, useState } from "react";

export interface TimelineStage {
  id: string;
  title: string;
  subtitle: string;
  icon: string;
  status: "pending" | "running" | "done" | "warning" | "error";
  detail?: string;
}

interface AnalysisTimelineProps {
  stages: TimelineStage[];
}

const STATUS_COLOR: Record<TimelineStage["status"], string> = {
  pending: "var(--text-muted)",
  running: "var(--accent-cyan)",
  done:    "var(--accent-green)",
  warning: "var(--accent-yellow)",
  error:   "var(--accent-red)",
};

const STATUS_BG: Record<TimelineStage["status"], string> = {
  pending: "rgba(255,255,255,0.03)",
  running: "rgba(0,229,255,0.08)",
  done:    "rgba(50,215,75,0.08)",
  warning: "rgba(255,214,10,0.08)",
  error:   "rgba(255,69,58,0.08)",
};

const STATUS_ICON: Record<TimelineStage["status"], string> = {
  pending: "◯",
  running: "◌",
  done:    "✓",
  warning: "⚠",
  error:   "✕",
};

export function buildStagesFromProfile(
  packageName: string,
  permCount: number,
  classCount: number,
  urlCount: number,
  certStatus: "TRUSTED" | "WARNING" | "UNTRUSTED",
  verdict: string
): TimelineStage[] {
  return [
    {
      id: "zip",
      title: "ZIP Extraction",
      subtitle: "JSZip APK archive unpack",
      icon: "📦",
      status: "done",
      detail: `${packageName} decompressed`,
    },
    {
      id: "manifest",
      title: "Manifest Decoded",
      subtitle: "Binary AXML → structured XML",
      icon: "📄",
      status: permCount >= 0 ? "done" : "error",
      detail: `${permCount} permissions extracted`,
    },
    {
      id: "dex",
      title: "DEX Analysis",
      subtitle: "Class names + string constants",
      icon: "🧬",
      status: classCount > 0 ? "done" : "warning",
      detail: `${classCount} classes sampled`,
    },
    {
      id: "cert",
      title: "Certificate Check",
      subtitle: "META-INF signer metadata",
      icon: "🔏",
      status: certStatus === "TRUSTED" ? "done" : certStatus === "WARNING" ? "warning" : "error",
      detail: `Signer status: ${certStatus}`,
    },
    {
      id: "strings",
      title: "String Analysis",
      subtitle: "URL / IP / secret pattern scan",
      icon: "🌐",
      status: urlCount > 0 ? "warning" : "done",
      detail: `${urlCount} network indicators`,
    },
    {
      id: "scoring",
      title: "Risk Score Computed",
      subtitle: "Rule-based weighted scoring",
      icon: "📊",
      status: "done",
      detail: `Verdict: ${verdict}`,
    },
    {
      id: "ai",
      title: "AI Narrative Generated",
      subtitle: "NVIDIA NIM Llama-3.1-70B",
      icon: "🤖",
      status: "done",
      detail: "Threat narrative ready",
    },
  ];
}

export default function AnalysisTimeline({ stages }: AnalysisTimelineProps) {
  const [visible, setVisible] = useState<Set<string>>(new Set());

  useEffect(() => {
    // Stagger reveal of each stage
    stages.forEach((stage, i) => {
      setTimeout(() => {
        setVisible((prev) => new Set([...prev, stage.id]));
      }, i * 120);
    });
  }, [stages]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0" }}>
      {stages.map((stage, idx) => {
        const isVisible = visible.has(stage.id);
        const isLast = idx === stages.length - 1;

        return (
          <div
            key={stage.id}
            style={{
              display: "flex",
              gap: "12px",
              opacity: isVisible ? 1 : 0,
              transform: isVisible ? "none" : "translateX(-8px)",
              transition: "opacity 0.3s ease, transform 0.3s ease",
            }}
          >
            {/* Connector column */}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: "28px", flexShrink: 0 }}>
              {/* Circle */}
              <div style={{
                width: "28px", height: "28px",
                borderRadius: "50%",
                background: STATUS_BG[stage.status],
                border: `2px solid ${STATUS_COLOR[stage.status]}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: "0.7rem", fontWeight: 800,
                color: STATUS_COLOR[stage.status],
                flexShrink: 0,
                ...(stage.status === "running" ? {
                  animation: "pulse 1.5s ease-in-out infinite",
                } : {}),
              }}>
                {STATUS_ICON[stage.status]}
              </div>
              {/* Vertical line */}
              {!isLast && (
                <div style={{
                  width: "2px",
                  flex: 1,
                  minHeight: "20px",
                  background: isVisible ? STATUS_COLOR[stage.status] : "var(--border-color)",
                  opacity: 0.35,
                  transition: "background 0.3s",
                }} />
              )}
            </div>

            {/* Content */}
            <div style={{ paddingBottom: isLast ? 0 : "16px", flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "2px" }}>
                <span style={{ fontSize: "0.85rem" }}>{stage.icon}</span>
                <span style={{ fontSize: "0.8rem", fontWeight: 800, color: "var(--text-primary)" }}>{stage.title}</span>
              </div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-secondary)" }}>{stage.subtitle}</div>
              {stage.detail && (
                <div className="mono" style={{
                  fontSize: "0.68rem",
                  color: STATUS_COLOR[stage.status],
                  marginTop: "4px",
                  fontWeight: 600,
                }}>
                  {stage.detail}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
