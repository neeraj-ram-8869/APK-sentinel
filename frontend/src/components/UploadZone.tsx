"use client";

// ===================================================================
// UploadZone — drag & drop APK upload with animated radar scanner
// ===================================================================

import { useCallback, useRef, useState } from "react";

interface UploadZoneProps {
  onFileSelected: (file: File) => void;
  isAnalyzing: boolean;
  fileName?: string | null;
  fileSize?: number | null;
}

function formatBytes(bytes: number): string {
  if (bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export default function UploadZone({ onFileSelected, isAnalyzing, fileName, fileSize }: UploadZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    (file: File) => {
      if (!file.name.toLowerCase().endsWith(".apk")) return;
      onFileSelected(file);
    },
    [onFileSelected]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      if (isAnalyzing) return;
      const f = e.dataTransfer.files?.[0];
      if (f) handleFile(f);
    },
    [handleFile, isAnalyzing]
  );

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); if (!isAnalyzing) setIsDragging(true); }}
      onDragLeave={(e) => { e.preventDefault(); setIsDragging(false); }}
      onDrop={onDrop}
      onClick={() => !isAnalyzing && inputRef.current?.click()}
      role="button"
      tabIndex={0}
      style={{
        position: "relative",
        flex: 1,
        display: "flex",
        alignItems: "center",
        gap: "16px",
        padding: "14px 20px",
        borderRadius: "10px",
        border: `2px dashed ${isDragging ? "var(--accent-cyan)" : "var(--border-color)"}`,
        background: isDragging ? "rgba(0,229,255,0.06)" : "rgba(255,255,255,0.015)",
        cursor: isAnalyzing ? "default" : "pointer",
        transition: "all 0.2s ease",
        overflow: "hidden",
        minHeight: "72px",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".apk"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
        style={{ display: "none" }}
      />

      {/* Radar / Icon */}
      <div style={{ position: "relative", width: 44, height: 44, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
        {isAnalyzing ? (
          <svg width="44" height="44" viewBox="0 0 44 44">
            <circle cx="22" cy="22" r="19" fill="none" stroke="var(--border-color)" strokeWidth="2" />
            <circle cx="22" cy="22" r="19" fill="none" stroke="var(--accent-cyan)" strokeWidth="2"
              strokeDasharray="40 80" strokeLinecap="round">
              <animateTransform attributeName="transform" type="rotate" from="0 22 22" to="360 22 22" dur="1.1s" repeatCount="indefinite" />
            </circle>
            <circle cx="22" cy="22" r="11" fill="none" stroke="var(--accent-purple)" strokeWidth="1.5" opacity="0.5"
              strokeDasharray="20 50" strokeLinecap="round">
              <animateTransform attributeName="transform" type="rotate" from="360 22 22" to="0 22 22" dur="1.8s" repeatCount="indefinite" />
            </circle>
          </svg>
        ) : (
          <div style={{
            width: 44, height: 44, borderRadius: "10px",
            background: "rgba(177,117,255,0.1)", border: "1px solid rgba(177,117,255,0.25)",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: "1.3rem",
          }}>
            📦
          </div>
        )}
      </div>

      {/* Text */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--text-primary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
          {isAnalyzing
            ? `Analyzing ${fileName ?? "APK"}...`
            : fileName
              ? fileName
              : "Drag & drop an .apk file here"}
        </div>
        <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "2px" }}>
          {isAnalyzing
            ? "Static reverse-engineering pipeline running"
            : fileSize
              ? `${formatBytes(fileSize)} · click to re-analyze a different file`
              : "or click to browse · supports .apk files only"}
        </div>
      </div>

      {!isAnalyzing && (
        <span style={{
          fontSize: "0.68rem", fontWeight: 700, color: "var(--accent-purple)",
          border: "1px solid rgba(177,117,255,0.35)", borderRadius: "999px",
          padding: "4px 12px", whiteSpace: "nowrap", flexShrink: 0,
        }}>
          BROWSE
        </span>
      )}
    </div>
  );
}
