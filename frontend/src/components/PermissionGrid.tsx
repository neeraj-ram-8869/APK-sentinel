"use client";

// ===================================================================
// Session 6 — PermissionGrid Component
// Color-coded heatmap of all declared permissions.
// ===================================================================

import { useState } from "react";

interface Permission {
  name: string;
  dangerous: boolean;
  status: "clean" | "suspicious" | "critical";
  details: string;
}

interface PermissionGridProps {
  permissions: Permission[];
}

const STATUS_COLOR = {
  critical:   { bg: "rgba(220,38,38,0.08)",  border: "rgba(220,38,38,0.25)",  text: "var(--accent-red)",    dot: "#dc2626" },
  suspicious: { bg: "rgba(217,119,6,0.08)",  border: "rgba(217,119,6,0.25)",  text: "var(--accent-yellow)", dot: "#d97706" },
  clean:      { bg: "rgba(5,150,105,0.05)",  border: "rgba(5,150,105,0.15)",  text: "var(--accent-green)",  dot: "#059669" },
};

const CATEGORIES: Array<{ label: string; filter: (p: Permission) => boolean }> = [
  { label: "All",       filter: () => true },
  { label: "Critical",  filter: (p) => p.status === "critical" },
  { label: "Dangerous", filter: (p) => p.status === "suspicious" },
  { label: "Clean",     filter: (p) => p.status === "clean" },
];

export default function PermissionGrid({ permissions }: PermissionGridProps) {
  const [activeFilter, setActiveFilter] = useState<string>("All");
  const [selectedPerm, setSelectedPerm] = useState<Permission | null>(null);

  const filtered = permissions.filter(
    CATEGORIES.find((c) => c.label === activeFilter)!.filter
  );

  const critCount  = permissions.filter((p) => p.status === "critical").length;
  const suspCount  = permissions.filter((p) => p.status === "suspicious").length;
  const cleanCount = permissions.filter((p) => p.status === "clean").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>

      {/* Summary row */}
      <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
        {[
          { label: "Critical", count: critCount,  color: "#dc2626" },
          { label: "Suspicious", count: suspCount,  color: "#d97706" },
          { label: "Clean",    count: cleanCount, color: "#059669" },
        ].map((s) => (
          <div key={s.label} style={{
            display: "flex", alignItems: "center", gap: "6px",
            background: "#f8fafc", border: "1px solid var(--border-subtle)",
            borderRadius: "6px", padding: "6px 12px",
            fontSize: "0.75rem", fontWeight: 700,
          }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: s.color }} />
            <span style={{ color: s.color }}>{s.count}</span>
            <span style={{ color: "var(--text-muted)" }}>{s.label}</span>
          </div>
        ))}
      </div>

      {/* Filter tabs */}
      <div style={{ display: "flex", gap: "6px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "1px" }}>
        {CATEGORIES.map((cat) => (
          <button
            key={cat.label}
            onClick={() => setActiveFilter(cat.label)}
            style={{
              background: activeFilter === cat.label ? "rgba(99,102,241,0.08)" : "transparent",
              color: activeFilter === cat.label ? "var(--accent-purple)" : "var(--text-secondary)",
              border: "none",
              borderBottom: `2px solid ${activeFilter === cat.label ? "var(--accent-purple)" : "transparent"}`,
              padding: "6px 12px",
              cursor: "pointer",
              fontSize: "0.75rem",
              fontWeight: 700,
              borderRadius: "4px 4px 0 0",
              transition: "all 0.15s",
            }}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {/* Grid */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
        gap: "8px",
      }}>
        {filtered.map((perm) => {
          const c = STATUS_COLOR[perm.status];
          const isSelected = selectedPerm?.name === perm.name;
          const shortName = perm.name.replace("android.permission.", "");

          return (
            <div
              key={perm.name}
              onClick={() => setSelectedPerm(isSelected ? null : perm)}
              style={{
                background: isSelected ? c.bg : "#f8fafc",
                border: `1px solid ${isSelected ? c.border : "var(--border-subtle)"}`,
                borderRadius: "6px",
                padding: "10px 12px",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
            >
              {/* Header */}
              <div style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
                <div style={{
                  width: "8px", height: "8px", borderRadius: "50%",
                  background: c.dot, flexShrink: 0, marginTop: "4px",
                }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="mono" style={{
                    fontSize: "0.72rem", fontWeight: 700, color: "#0f172a",
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>
                    {shortName}
                  </div>
                  {isSelected && (
                    <div style={{
                      fontSize: "0.7rem", color: "var(--text-secondary)",
                      marginTop: "6px", lineHeight: 1.45,
                    }}>
                      {perm.details}
                    </div>
                  )}
                </div>
                <span style={{
                  background: c.bg, color: c.text,
                  border: `1px solid ${c.border}`,
                  padding: "1px 6px", borderRadius: "3px",
                  fontSize: "0.62rem", fontWeight: 800, flexShrink: 0,
                }}>
                  {perm.status.toUpperCase()}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div style={{ textAlign: "center", color: "var(--text-muted)", fontSize: "0.8rem", padding: "24px" }}>
          No permissions in this category.
        </div>
      )}
    </div>
  );
}
