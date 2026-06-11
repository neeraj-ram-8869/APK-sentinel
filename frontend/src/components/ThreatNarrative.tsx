"use client";
// ===================================================================
// Session 4 — ThreatNarrative Component
// Streaming-style display of AI-generated threat narrative with
// typing animation and NIM source badge.
// ===================================================================
import { useEffect, useRef, useState } from "react";

interface ThreatNarrativeProps {
  text: string;
  isTyping: boolean;
  source?: "nim" | "fallback";
}

export default function ThreatNarrative({ text, isTyping, source = "fallback" }: ThreatNarrativeProps) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h5 style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>
          AI Threat Narrative
        </h5>
        <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
          {source === "nim" ? (
            <span style={{
              background: "rgba(99,102,241,0.08)", color: "var(--accent-purple)",
              border: "1px solid rgba(99,102,241,0.2)", fontSize: "0.65rem",
              padding: "2px 8px", borderRadius: "4px", fontWeight: 700, fontFamily: "var(--font-mono)"
            }}>
              ⚡ NVIDIA NIM
            </span>
          ) : (
            <span style={{
              background: "rgba(100,116,139,0.08)", color: "var(--text-muted)",
              border: "1px solid var(--border-subtle)", fontSize: "0.65rem",
              padding: "2px 8px", borderRadius: "4px", fontWeight: 700, fontFamily: "var(--font-mono)"
            }}>
              DETERMINISTIC
            </span>
          )}
        </div>
      </div>

      {/* Narrative body */}
      <div style={{
        background: "#f8fafc", border: "1px solid var(--border-subtle)",
        borderRadius: "4px", padding: "20px",
        fontSize: "0.82rem", fontFamily: "var(--font-mono)",
        lineHeight: 1.75, color: "var(--text-primary)",
        minHeight: "180px", whiteSpace: "pre-wrap", position: "relative",
      }}>
        {/* Colorize lines by prefix */}
        {text.split("\n").map((line, i) => {
          const color =
            line.startsWith("[CRITICAL]") || line.startsWith("ERROR") ? "var(--accent-red)"
            : line.startsWith("[HIGH]") || line.startsWith("WARN")    ? "var(--accent-orange)"
            : line.match(/^\d+\./)                                     ? "var(--accent-cyan)"
            : "var(--text-primary)";
          return (
            <div key={i} style={{ color, marginBottom: line === "" ? "8px" : "0" }}>
              {line || "\u00A0"}
            </div>
          );
        })}

        {/* Blinking cursor */}
        {isTyping && (
          <span style={{
            width: "6px", height: "14px", background: "var(--accent-purple)",
            display: "inline-block", marginLeft: "2px", verticalAlign: "middle",
            animation: "blink 1s step-end infinite",
          }} />
        )}
      </div>

      {/* NIM upgrade hint when running fallback */}
      {source === "fallback" && !isTyping && text && (
        <div style={{
          fontSize: "0.68rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)",
          background: "rgba(148,163,184,0.05)", border: "1px dashed var(--border-subtle)",
          borderRadius: "4px", padding: "8px 12px",
        }}>
          💡 Set <span style={{ color: "var(--accent-cyan)" }}>NVIDIA_API_KEY</span> in{" "}
          <span style={{ color: "var(--accent-purple)" }}>.env.local</span> to enable live NVIDIA NIM narratives.
        </div>
      )}
    </div>
  );
}
