"use client";
// ===================================================================
// Session 7 — PdfReport Download Button with Generation Progress
// ===================================================================
import { useState } from "react";
import { generateThreatReport, type ReportProfile } from "@/lib/pdf/report-generator";

interface PdfReportProps {
  profile: ReportProfile;
  onToast?: (type: "success" | "error" | "info", title: string, message?: string) => void;
}

export default function PdfReport({ profile, onToast }: PdfReportProps) {
  const [state, setState] = useState<"idle" | "generating" | "done" | "error">("idle");

  const handleGenerate = () => {
    setState("generating");
    onToast?.("info", "Generating Report", "Compiling official threat metrics…");

    // Small timeout to allow the UI to update before the synchronous jsPDF work
    setTimeout(() => {
      try {
        generateThreatReport(profile);
        setState("done");
        onToast?.("success", "Threat Report Saved", "Successfully generated official threat analysis report.");
        setTimeout(() => setState("idle"), 3000);
      } catch (err) {
        setState("error");
        onToast?.("error", "Report Failed", err instanceof Error ? err.message : "PDF generation failed.");
        setTimeout(() => setState("idle"), 3000);
      }
    }, 80);
  };

  const label =
    state === "generating" ? "Generating…"
    : state === "done"      ? "✓ Downloaded"
    : state === "error"     ? "✗ Failed"
    : "Export Threat Report";

  const bg =
    state === "done"  ? "var(--accent-green)"
    : state === "error" ? "var(--accent-red)"
    : "var(--accent-purple)";

  return (
    <button
      onClick={handleGenerate}
      disabled={state === "generating"}
      style={{
        background: bg,
        color: "#ffffff",
        border: "none",
        borderRadius: "6px",
        fontWeight: 700,
        padding: "10px 18px",
        display: "flex",
        alignItems: "center",
        gap: "8px",
        cursor: state === "generating" ? "not-allowed" : "pointer",
        opacity: state === "generating" ? 0.8 : 1,
        transition: "all 0.2s",
        boxShadow: "0 2px 4px rgba(99,102,241,0.15)",
        fontSize: "0.85rem",
      }}
    >
      {state === "generating" && (
        <span style={{
          width: "14px", height: "14px",
          border: "2px solid rgba(255,255,255,0.4)",
          borderTopColor: "white",
          borderRadius: "50%",
          display: "inline-block",
          animation: "spin 0.8s linear infinite",
        }} />
      )}
      {label}
    </button>
  );
}
