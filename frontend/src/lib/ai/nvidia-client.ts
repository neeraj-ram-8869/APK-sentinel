// ===================================================================
// Session 4 — Client-side NVIDIA NIM caller
// Calls /api/analyze — never touches the API key directly.
// ===================================================================

import type { NarrativePayload, ChatPayload } from "@/app/api/analyze/route";

export type { NarrativePayload, ChatPayload };

interface ApiResponse {
  text: string;
  source: "nim" | "fallback";
}

// ── Narrative ──────────────────────────────────────────────────────

export async function generateThreatNarrative(
  payload: NarrativePayload
): Promise<{ text: string; fromNim: boolean }> {
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode: "narrative", payload }),
  });

  if (!res.ok) {
    throw new Error(`/api/analyze returned HTTP ${res.status}`);
  }

  const data = (await res.json()) as ApiResponse;
  return { text: data.text, fromNim: data.source === "nim" };
}

// ── Chat ───────────────────────────────────────────────────────────

export async function askNimAnalyst(
  payload: ChatPayload
): Promise<{ text: string; fromNim: boolean }> {
  const res = await fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode: "chat", payload }),
  });

  if (!res.ok) {
    throw new Error(`/api/analyze returned HTTP ${res.status}`);
  }

  const data = (await res.json()) as ApiResponse;
  return { text: data.text, fromNim: data.source === "nim" };
}

// ── Helper: build NarrativePayload from ApkProfile ────────────────

export interface MinimalProfileData {
  packageName: string;
  fileName: string;
  verdict: string;
  score: number;
  permissions: Array<{ name: string; dangerous: boolean }>;
  urls: string[];
  ips: string[];
  apis: Array<{ name: string }>;
  keyFindings: Array<{ severity: string; scope: string; label: string; details: string }>;
  isDebuggable?: boolean;
  debugKey?: boolean;
  classCount?: number;
  stringCount?: number;
}

export function buildNarrativePayload(profile: MinimalProfileData): NarrativePayload {
  return {
    packageName: profile.packageName,
    fileName: profile.fileName,
    verdict: profile.verdict,
    score: profile.score,
    permissions: profile.permissions.map((p) => p.name),
    dangerousPermissions: profile.permissions
      .filter((p) => p.dangerous)
      .map((p) => p.name),
    urls: profile.urls,
    ips: profile.ips,
    sdks: profile.apis.map((a) => a.name),
    findings: profile.keyFindings.map((f) => ({
      severity: f.severity,
      scope: f.scope,
      title: f.label,
      description: f.details,
    })),
    isDebuggable: profile.isDebuggable ?? false,
    debugKey: profile.debugKey ?? false,
    classCount: profile.classCount ?? 0,
    stringCount: profile.stringCount ?? 0,
  };
}
