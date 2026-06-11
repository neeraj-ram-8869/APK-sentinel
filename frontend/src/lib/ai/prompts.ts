// ===================================================================
// Session 4 — NVIDIA NIM Prompt Templates
// ===================================================================

import type { NarrativePayload, ChatPayload } from "@/app/api/analyze/route";

export const SYSTEM_PROMPT = `You are APK Sentinel's AI threat analyst, powered by NVIDIA NIM (Llama-3.1-8B).
You specialize in Android mobile security, static APK analysis, reverse engineering, and malware identification.
Your outputs are concise, technical, and structured for security professionals.
You base responses strictly on the provided analysis data — never speculate beyond the evidence.
Format narratives with numbered sections and bullet points. Keep responses under 800 tokens.`;

// ===========================
// Threat Narrative Prompt
// ===========================

export function buildThreatNarrativePrompt(p: NarrativePayload): string {
  const findingsText = p.findings.length > 0
    ? p.findings.slice(0, 8).map(
        (f) => `  [${f.severity}] ${f.scope} — ${f.title}: ${f.description}`
      ).join("\n")
    : "  No structured findings generated.";

  const permissionsText = p.dangerousPermissions.length > 0
    ? p.dangerousPermissions.slice(0, 8).map((perm) => `  • ${perm}`).join("\n")
    : "  No dangerous permissions declared.";

  const networkText = [...p.urls.slice(0, 4), ...p.ips.slice(0, 4)].join(", ") || "none";

  return `
Analyze the following APK and produce a structured threat narrative with 4 numbered sections:
1. Application Identity & Risk Classification
2. Permission & Component Threat Assessment
3. Static Code & Network Indicator Analysis
4. Verdict Summary with remediation recommendation

=== APK ANALYSIS DATA ===
Package:        ${p.packageName}
File:           ${p.fileName}
Verdict:        ${p.verdict}
Risk Score:     ${p.score}/100
Debuggable:     ${p.isDebuggable}
Debug Key:      ${p.debugKey}
Class Count:    ${p.classCount}
String Samples: ${p.stringCount}

=== DANGEROUS PERMISSIONS (${p.dangerousPermissions.length}) ===
${permissionsText}

=== STRUCTURED FINDINGS (${p.findings.length}) ===
${findingsText}

=== EMBEDDED NETWORK INDICATORS ===
URLs: ${p.urls.slice(0, 4).join(", ") || "none"}
IPs:  ${p.ips.slice(0, 4).join(", ") || "none"}

=== DETECTED SDKs ===
${p.sdks.length > 0 ? p.sdks.slice(0, 4).join(", ") : "none"}

Produce the narrative now. Use the section format above. Be technical and specific to this APK's data.
`.trim();
}

// ===========================
// Chat Response Prompt
// ===========================

export function buildChatResponsePrompt(p: ChatPayload): string {
  const ctx = p.context;
  const historyText = p.history.length > 0
    ? p.history.slice(-6).map((m) => `${m.role === "user" ? "Auditor" : "Analyst"}: ${m.content}`).join("\n")
    : "No previous messages.";

  return `
You are answering questions about the following APK analysis.

=== CURRENT APK CONTEXT ===
Package:   ${ctx.packageName}
Verdict:   ${ctx.verdict}
Score:     ${ctx.score}/100
Debug Key: ${ctx.debugKey}
Permissions (dangerous): ${ctx.dangerousPermissions.slice(0, 6).map((p) => p.replace("android.permission.", "")).join(", ") || "none"}
Findings:  ${ctx.findings.length} (${ctx.findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length} HIGH+CRITICAL)
URLs:      ${ctx.urls.slice(0, 3).join(", ") || "none"}
IPs:       ${ctx.ips.slice(0, 3).join(", ") || "none"}
SDKs:      ${ctx.sdks.slice(0, 3).join(", ") || "none"}

=== CONVERSATION HISTORY ===
${historyText}

=== AUDITOR QUESTION ===
${p.question}

Respond concisely (2-4 sentences max) as a professional Android security analyst. Reference specific evidence from the context above.
`.trim();
}
