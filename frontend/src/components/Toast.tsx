"use client";

// ===================================================================
// Lightweight toast notification system (no external deps)
// ===================================================================

import { useEffect } from "react";

export interface ToastItem {
  id: number;
  type: "success" | "error" | "warning" | "info";
  title: string;
  message?: string;
}

const ICONS: Record<ToastItem["type"], string> = {
  success: "✓",
  error: "✕",
  warning: "⚠",
  info: "ℹ",
};

const COLORS: Record<ToastItem["type"], string> = {
  success: "var(--accent-green)",
  error: "var(--accent-red)",
  warning: "var(--accent-yellow)",
  info: "var(--accent-cyan)",
};

interface ToastContainerProps {
  toasts: ToastItem[];
  onDismiss: (id: number) => void;
}

function Toast({ toast, onDismiss }: { toast: ToastItem; onDismiss: (id: number) => void }) {
  useEffect(() => {
    const t = setTimeout(() => onDismiss(toast.id), 5000);
    return () => clearTimeout(t);
  }, [toast.id, onDismiss]);

  return (
    <div
      className="toast-item"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: "12px",
        background: "var(--bg-card)",
        border: `1px solid ${COLORS[toast.type]}40`,
        borderLeft: `3px solid ${COLORS[toast.type]}`,
        borderRadius: "8px",
        padding: "12px 14px",
        minWidth: "280px",
        maxWidth: "360px",
        boxShadow: "0 8px 24px rgba(0,0,0,0.35)",
        animation: "toastIn 0.3s cubic-bezier(0.16, 1, 0.3, 1)",
      }}
    >
      <div
        style={{
          width: "22px",
          height: "22px",
          borderRadius: "50%",
          flexShrink: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: "0.7rem",
          fontWeight: 800,
          color: COLORS[toast.type],
          background: `${COLORS[toast.type]}1A`,
          border: `1px solid ${COLORS[toast.type]}40`,
        }}
      >
        {ICONS[toast.type]}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: "0.8rem", fontWeight: 700, color: "var(--text-primary)" }}>{toast.title}</div>
        {toast.message && (
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "2px", lineHeight: 1.4 }}>
            {toast.message}
          </div>
        )}
      </div>
      <button
        onClick={() => onDismiss(toast.id)}
        aria-label="Dismiss"
        style={{
          background: "transparent",
          border: "none",
          color: "var(--text-muted)",
          cursor: "pointer",
          fontSize: "0.85rem",
          lineHeight: 1,
          padding: 0,
        }}
      >
        ✕
      </button>
    </div>
  );
}

export default function ToastContainer({ toasts, onDismiss }: ToastContainerProps) {
  if (toasts.length === 0) return null;
  return (
    <div
      style={{
        position: "fixed",
        top: "16px",
        right: "16px",
        zIndex: 9999,
        display: "flex",
        flexDirection: "column",
        gap: "10px",
      }}
    >
      {toasts.map((t) => (
        <Toast key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  );
}
