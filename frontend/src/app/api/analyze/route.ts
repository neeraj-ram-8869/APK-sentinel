// ===================================================================
// Session 4 — NVIDIA NIM Threat Narrative API Route
// POST /api/analyze
//
// Accepts a structured APK analysis payload and returns a threat
// narrative from NVIDIA NIM (Llama-3.1-70B).  Falls back to a
// deterministic narrative when no API key is configured.
// ===================================================================

import { NextRequest, NextResponse } from "next/server";
import { buildThreatNarrativePrompt, buildChatResponsePrompt, SYSTEM_PROMPT } from "@/lib/ai/prompts";

const NVIDIA_BASE_URL = process.env.NVIDIA_BASE_URL ?? "https://integrate.api.nvidia.com/v1";
const NVIDIA_API_KEY  = process.env.NVIDIA_API_KEY  ?? "";
const NVIDIA_MODEL    = process.env.NVIDIA_MODEL    ?? "meta/llama-3.1-70b-instruct";

const KEY_CONFIGURED =
  Boolean(NVIDIA_API_KEY) &&
  NVIDIA_API_KEY !== "your_nvidia_api_key_here";

export interface AnalyzeRequestBody {
  mode: "narrative" | "chat";
  payload: NarrativePayload | ChatPayload;
}

export interface NarrativePayload {
  packageName: string;
  fileName: string;
  verdict: string;
  score: number;
  permissions: string[];
  dangerousPermissions: string[];
  urls: string[];
  ips: string[];
  sdks: string[];
  findings: Array<{ severity: string; scope: string; title: string; description: string }>;
  isDebuggable: boolean;
  debugKey: boolean;
  classCount: number;
  stringCount: number;
}

export interface ChatPayload {
  question: string;
  context: NarrativePayload;
  history: Array<{ role: "user" | "assistant"; content: string }>;
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  let body: AnalyzeRequestBody;
  try {
    body = (await req.json()) as AnalyzeRequestBody;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const userPrompt =
    body.mode === "chat"
      ? buildChatResponsePrompt(body.payload as ChatPayload)
      : buildThreatNarrativePrompt(body.payload as NarrativePayload);

  // ── No key configured ─────────────────────────────────────────────
  if (!KEY_CONFIGURED) {
    const fallback =
      body.mode === "chat"
        ? buildFallbackChatResponse(body.payload as ChatPayload)
        : buildFallbackNarrative(body.payload as NarrativePayload);
    return NextResponse.json({ text: fallback, source: "fallback" });
  }

  // ── NVIDIA NIM API call ───────────────────────────────────────────
  try {
    const history =
      body.mode === "chat"
        ? (body.payload as ChatPayload).history.map((m) => ({
            role: m.role,
            content: m.content,
          }))
        : [];

    const nimResponse = await fetch(`${NVIDIA_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${NVIDIA_API_KEY}`,
      },
      body: JSON.stringify({
        model: NVIDIA_MODEL,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          ...history,
          { role: "user", content: userPrompt },
        ],
        max_tokens: body.mode === "chat" ? 512 : 900,
        temperature: 0.3,
        top_p: 0.9,
        stream: false,
      }),
    });

    if (!nimResponse.ok) {
      const errorText = await nimResponse.text().catch(() => "");
      console.error(`[NIM] HTTP ${nimResponse.status}: ${errorText}`);
      throw new Error(`NIM HTTP ${nimResponse.status}`);
    }

    const nimData = (await nimResponse.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };

    const text = nimData.choices?.[0]?.message?.content?.trim() ?? "";
    if (!text) throw new Error("NIM returned empty content");

    return NextResponse.json({ text, source: "nim" });
  } catch (err) {
    console.error("[NIM] Falling back to deterministic narrative:", err);
    const fallback =
      body.mode === "chat"
        ? buildFallbackChatResponse(body.payload as ChatPayload)
        : buildFallbackNarrative(body.payload as NarrativePayload);
    return NextResponse.json({ text: fallback, source: "fallback" });
  }
}

// ===================================================================
// Deterministic fallback narrative (no API key required)
// ===================================================================

function buildFallbackNarrative(p: NarrativePayload): string {
  const lines: string[] = [];

  lines.push(`APK Sentinel Static Analysis Narrative`);
  lines.push(`Package: ${p.packageName}`);
  lines.push(`Risk Score: ${p.score}/100 — Verdict: ${p.verdict}`);
  lines.push(``);

  if (p.dangerousPermissions.length > 0) {
    lines.push(`1. Dangerous Permission Profile`);
    lines.push(
      `   The manifest declares ${p.permissions.length} permissions, of which ${p.dangerousPermissions.length} are flagged as dangerous:`
    );
    p.dangerousPermissions.slice(0, 5).forEach((perm) => {
      lines.push(`   • ${perm.replace("android.permission.", "")}`);
    });
    lines.push(``);
  }

  if (p.findings.length > 0) {
    lines.push(`2. Structured Findings Summary`);
    p.findings.slice(0, 5).forEach((f) => {
      lines.push(`   [${f.severity}] ${f.scope}: ${f.title}`);
      lines.push(`   → ${f.description}`);
    });
    lines.push(``);
  }

  if (p.urls.length > 0 || p.ips.length > 0) {
    lines.push(`3. Embedded Network Indicators`);
    p.urls.slice(0, 3).forEach((url) => lines.push(`   URL: ${url}`));
    p.ips.slice(0, 3).forEach((ip) => lines.push(`   IP:  ${ip}`));
    lines.push(``);
  }

  if (p.sdks.length > 0) {
    lines.push(`4. Detected SDK / Library Patterns`);
    p.sdks.slice(0, 3).forEach((sdk) => lines.push(`   • ${sdk}`));
    lines.push(``);
  }

  lines.push(`5. Certificate Integrity`);
  lines.push(
    p.debugKey
      ? `   WARN: APK is signed with a debug key — production hardening absent.`
      : `   Certificate metadata does not indicate a debug-only signing key.`
  );

  lines.push(``);
  lines.push(
    `[Note: NVIDIA NIM API key is not configured. Set NVIDIA_API_KEY in .env.local for AI-generated narratives.]`
  );

  return lines.join("\n");
}

function buildFallbackChatResponse(p: ChatPayload): string {
  const q = p.question.toLowerCase();
  const ctx = p.context;

  if (q.includes("score") || q.includes("risk") || q.includes("rating")) {
    return `Risk index is ${ctx.score}/100 (verdict: ${ctx.verdict}). Primary factors: ${ctx.dangerousPermissions.length} dangerous permissions, ${ctx.findings.length} structured findings, and ${ctx.urls.length + ctx.ips.length} network indicators.`;
  }
  if (q.includes("permission")) {
    return `Package declares ${ctx.permissions.length} permissions. Dangerous subset: ${ctx.dangerousPermissions.slice(0, 4).map((p) => p.replace("android.permission.", "")).join(", ") || "none"}.`;
  }
  if (q.includes("cert") || q.includes("signature") || q.includes("sign")) {
    return ctx.debugKey
      ? `Certificate is a debug key — this indicates a repackaged or test build not suitable for production.`
      : `Certificate metadata does not show a debug signing key.`;
  }
  if (q.includes("url") || q.includes("ip") || q.includes("network") || q.includes("c2")) {
    return ctx.urls.length + ctx.ips.length > 0
      ? `Found ${ctx.urls.length} embedded URLs and ${ctx.ips.length} raw IPs in DEX string tables. Top: ${[...ctx.urls.slice(0, 2), ...ctx.ips.slice(0, 2)].join(", ")}.`
      : `No embedded network indicators were found in DEX string tables.`;
  }
  if (q.includes("sdk") || q.includes("librar")) {
    return ctx.sdks.length > 0
      ? `Detected ${ctx.sdks.length} SDK/library pattern(s): ${ctx.sdks.slice(0, 3).join(", ")}.`
      : `No known third-party SDK patterns matched in class or string tables.`;
  }
  return `Package ${ctx.packageName} received verdict ${ctx.verdict} with score ${ctx.score}/100. ${ctx.findings.length} findings identified. Ask me about permissions, signatures, network indicators, or risk breakdown.`;
}
