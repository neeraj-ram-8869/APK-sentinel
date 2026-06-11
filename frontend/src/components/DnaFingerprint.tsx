"use client";
// ===================================================================
// Session 5 — DnaFingerprint Canvas Component
// Extracted from page.tsx and driven by fingerprint data generator.
// ===================================================================
import { useRef, useEffect, useCallback } from "react";
import { generateFingerprint } from "@/lib/dna/fingerprint";

interface DnaFingerprintProps {
  verdict: "BENIGN" | "SUSPICIOUS" | "FRAUDULENT" | "MALICIOUS";
  score: number;
  criticalPermissions: number;
  suspiciousPermissions: number;
  permissionCount: number;
  highRiskApis?: number;
  urlCount?: number;
  ipCount?: number;
  classCount?: number;
  isDebuggable?: boolean;
  debugKey?: boolean;
  progress?: number; // 0–100, defaults to 100 (fully drawn)
  size?: number;
}

export default function DnaFingerprint({
  verdict, score,
  criticalPermissions, suspiciousPermissions, permissionCount,
  highRiskApis = 0, urlCount = 0, ipCount = 0, classCount = 0,
  isDebuggable = false, debugKey = false,
  progress = 100,
  size = 240,
}: DnaFingerprintProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const fp = generateFingerprint({
      score, verdict, permissionCount, criticalPermissions,
      suspiciousPermissions, highRiskApis, urlCount, ipCount,
      classCount, isDebuggable, debugKey,
    });

    const w   = canvas.width;
    const h   = canvas.height;
    const cx  = w / 2;
    const cy  = h / 2;
    const pct = progress / 100;

    ctx.clearRect(0, 0, w, h);

    // ── Background rings ───────────────────────────────────────────
    ctx.strokeStyle = "rgba(100, 116, 139, 0.08)";
    ctx.lineWidth = 1;
    for (let r = 30; r <= 110; r += 15) {
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();
    }

    // ── Outer ring ─────────────────────────────────────────────────
    if (pct > 0.1) {
      const drawPct = Math.min(1, (pct - 0.1) / 0.7);
      ctx.lineWidth = 6;
      for (const seg of fp.outerSegments) {
        ctx.beginPath();
        ctx.arc(cx, cy, 110, seg.angle, seg.angle + seg.span * drawPct);
        ctx.strokeStyle = seg.color;
        ctx.globalAlpha = seg.opacity;
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }

    // ── Middle ring ────────────────────────────────────────────────
    if (pct > 0.5) {
      const drawPct = Math.min(1, (pct - 0.5) / 0.3);
      ctx.lineWidth = 10;
      for (const seg of fp.middleSegments) {
        ctx.beginPath();
        ctx.arc(cx, cy, 85, seg.angle, seg.angle + seg.span * drawPct);
        ctx.strokeStyle = seg.color;
        ctx.globalAlpha = seg.opacity;
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }

    // ── Inner ring ─────────────────────────────────────────────────
    if (pct > 0.8) {
      const drawPct = Math.min(1, (pct - 0.8) / 0.2);
      ctx.lineWidth = 4;
      ctx.strokeStyle = fp.innerColor;
      ctx.globalAlpha = 0.7;
      ctx.beginPath();
      ctx.arc(cx, cy, 60, 0, Math.PI * 2 * drawPct);
      ctx.stroke();
      ctx.globalAlpha = 1;
    }

    // ── Core glow ──────────────────────────────────────────────────
    if (pct > 0.9) {
      const pulseR  = 12 + Math.sin(Date.now() / 200) * 2;
      const gradient = ctx.createRadialGradient(cx, cy, 2, cx, cy, pulseR);
      gradient.addColorStop(0, fp.coreColor);
      gradient.addColorStop(1, "transparent");
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(cx, cy, pulseR, 0, Math.PI * 2);
      ctx.fill();
    }
  }, [verdict, score, criticalPermissions, suspiciousPermissions, permissionCount,
      highRiskApis, urlCount, ipCount, classCount, isDebuggable, debugKey, progress]);

  useEffect(() => {
    let animId: number;
    const tick = () => {
      draw();
      animId = requestAnimationFrame(tick);
    };
    tick();
    return () => cancelAnimationFrame(animId);
  }, [draw]);

  return (
    <canvas
      ref={canvasRef}
      width={size}
      height={size}
      style={{ maxWidth: `${Math.round(size * 0.71)}px`, maxHeight: `${Math.round(size * 0.71)}px` }}
    />
  );
}
