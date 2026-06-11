// ===================================================================
// Session 7 — Enhanced jsPDF Multi-section Threat Report Generator
// ===================================================================

import { jsPDF } from "jspdf";

export interface ReportProfile {
  fileName: string;
  fileSize: number;
  packageName: string;
  version: string;
  minSdk: string;
  targetSdk: string;
  score: number;
  verdict: "BENIGN" | "SUSPICIOUS" | "FRAUDULENT" | "MALICIOUS";
  confidence: string;
  category: string;
  signature: {
    issuer: string;
    subject: string;
    selfSigned: boolean;
    debugKey: boolean;
    status: "TRUSTED" | "WARNING" | "UNTRUSTED";
  };
  permissions: Array<{ name: string; status: "clean" | "suspicious" | "critical"; details: string }>;
  keyFindings: Array<{ id: string; scope: string; label: string; details: string; severity: string }>;
  urls: string[];
  ips: string[];
  apis: Array<{ name: string; category: string; danger: string }>;
  threatNarrative: string;
  virusTotal?: {
    found: boolean;
    stats?: { malicious: number; suspicious: number; undetected: number; harmless: number };
    permalink?: string;
  };
}

// ── Colors ────────────────────────────────────────────────────────────

function verdictRgb(verdict: ReportProfile["verdict"]): [number, number, number] {
  switch (verdict) {
    case "MALICIOUS":  return [220, 38,  38];
    case "FRAUDULENT": return [234, 88,  12];
    case "SUSPICIOUS": return [217, 119, 6];
    default:           return [5,   150, 105];
  }
}

function severityRgb(severity: string): [number, number, number] {
  switch (severity.toUpperCase()) {
    case "CRITICAL":
    case "HIGH":   return [220, 38, 38];
    case "MEDIUM": return [217, 119, 6];
    default:       return [5, 150, 105];
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

// ── Header banner ──────────────────────────────────────────────────────

function drawHeader(doc: jsPDF, p: ReportProfile, pageWidth: number): void {
  // Dark navy background
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 42, "F");

  // Accent stripe (verdict color)
  const [r, g, b] = verdictRgb(p.verdict);
  doc.setFillColor(r, g, b);
  doc.rect(0, 0, 4, 42, "F");

  // Title
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(15);
  doc.text("APK SENTINEL — AUTOMATED THREAT REPORT", 10, 17);

  // Subtitle
  doc.setFont("courier", "normal");
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text(`apkman Static Parser + aparoid Dynamic Traces + NVIDIA NIM AI`, 10, 26);
  doc.text(`Generated: ${new Date().toLocaleString()}   |   Ref: SENTINEL-${p.verdict}-${Date.now().toString().slice(-6)}`, 10, 33);
}

// ── Section heading ────────────────────────────────────────────────────

function sectionHeading(doc: jsPDF, title: string, y: number, pageWidth: number): number {
  doc.setFillColor(241, 245, 249);
  doc.rect(0, y, pageWidth, 10, "F");
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.text(title, 14, y + 7);
  return y + 14;
}

// ── Verdict box ────────────────────────────────────────────────────────

function drawVerdictBox(doc: jsPDF, p: ReportProfile, x: number, y: number): void {
  const [r, g, b] = verdictRgb(p.verdict);
  doc.setFillColor(248, 250, 252);
  doc.rect(x, y, 66, 36, "F");
  doc.setDrawColor(226, 232, 240);
  doc.rect(x, y, 66, 36, "S");
  doc.setFillColor(r, g, b);
  doc.rect(x, y, 66, 3, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  doc.text("VERDICT", x + 4, y + 10);
  doc.text("RISK SCORE", x + 4, y + 22);

  doc.setFontSize(13);
  doc.setTextColor(r, g, b);
  doc.text(p.verdict, x + 4, y + 18);

  doc.setFontSize(13);
  doc.setTextColor(15, 23, 42);
  doc.text(`${p.score}/100`, x + 4, y + 30);

  doc.setFontSize(7.5);
  doc.setTextColor(100, 116, 139);
  doc.text(`Confidence: ${p.confidence}`, x + 4, y + 36);
}

// ── Key-value table ────────────────────────────────────────────────────

function kvRow(
  doc: jsPDF,
  label: string,
  value: string,
  y: number,
  shade: boolean
): number {
  if (shade) {
    doc.setFillColor(248, 250, 252);
    doc.rect(14, y - 4, 182, 10, "F");
  }
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(100, 116, 139);
  doc.text(label, 14, y + 2);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(15, 23, 42);
  const lines = doc.splitTextToSize(value, 130);
  doc.text(lines, 68, y + 2);
  return y + Math.max(10, lines.length * 5);
}

// ── Main export function ───────────────────────────────────────────────

export function generateThreatReport(p: ReportProfile): void {
  const doc = new jsPDF({ unit: "mm", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 0;

  // ── Page 1 ────────────────────────────────────────────────────────

  drawHeader(doc, p, pageWidth);
  y = 52;

  // ─ Section 1: Application Identity ─

  y = sectionHeading(doc, "1. APPLICATION IDENTITY", y, pageWidth);
  y = kvRow(doc, "File",          p.fileName,                   y, true);
  y = kvRow(doc, "Size",          formatBytes(p.fileSize),       y, false);
  y = kvRow(doc, "Package",       p.packageName,                 y, true);
  y = kvRow(doc, "Version",       p.version,                     y, false);
  y = kvRow(doc, "Min SDK",       p.minSdk,                      y, true);
  y = kvRow(doc, "Target SDK",    p.targetSdk,                   y, false);
  y = kvRow(doc, "Category",      p.category,                    y, true);
  y += 4;

  // Verdict box (top-right overlay)
  drawVerdictBox(doc, p, 128, 56);

  // ─ Section 2: Certificate Integrity ─

  y = sectionHeading(doc, "2. CERTIFICATE INTEGRITY", y, pageWidth);
  y = kvRow(doc, "Issuer CN",     p.signature.issuer,            y, true);
  y = kvRow(doc, "Subject",       p.signature.subject,           y, false);
  y = kvRow(doc, "Status",        p.signature.status,            y, true);
  y = kvRow(doc, "Self-Signed",   p.signature.selfSigned ? "YES ⚠" : "NO", y, false);
  y = kvRow(doc, "Debug Key",     p.signature.debugKey ? "YES — NON-COMPLIANT" : "NO", y, true);
  y += 6;

  // ─ Section 3: Dangerous Permissions ─

  const dangerous = p.permissions.filter((p) => p.status !== "clean");
  y = sectionHeading(doc, `3. DANGEROUS PERMISSIONS (${dangerous.length} of ${p.permissions.length})`, y, pageWidth);

  for (let i = 0; i < Math.min(dangerous.length, 8); i++) {
    const perm = dangerous[i];
    const [r, g, b] = perm.status === "critical" ? [220, 38, 38] : [217, 119, 6];
    doc.setFillColor(r, g, b);
    doc.circle(17, y + 2.5, 1.5, "F");
    doc.setFont("courier", "normal");
    doc.setFontSize(8);
    doc.setTextColor(15, 23, 42);
    const shortName = perm.name.replace("android.permission.", "");
    doc.text(shortName, 21, y + 4);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    const detailLines = doc.splitTextToSize(perm.details, 158);
    doc.text(detailLines, 21, y + 8);
    y += 6 + detailLines.length * 4;
    if (y > 265) {
      doc.addPage();
      y = 20;
    }
  }
  y += 4;

  // ─ Section 4: Key Findings ─

  if (y > 220) {
    doc.addPage();
    y = 20;
  }
  y = sectionHeading(doc, `4. STRUCTURED FINDINGS (${p.keyFindings.length})`, y, pageWidth);

  for (let i = 0; i < Math.min(p.keyFindings.length, 8); i++) {
    const finding = p.keyFindings[i];
    const [r, g, b] = severityRgb(finding.severity);

    doc.setFillColor(r, g, b, 0.12);
    doc.rect(14, y - 1, 182, 1, "F");

    doc.setFont("courier", "bold");
    doc.setFontSize(7.5);
    doc.setTextColor(r, g, b);
    doc.text(`[${finding.severity}] ${finding.id}`, 14, y + 4);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`${finding.scope}: ${finding.label}`, 14, y + 9);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    const detailLines = doc.splitTextToSize(finding.details, 180);
    doc.text(detailLines, 14, y + 14);
    y += 14 + detailLines.length * 4 + 3;

    if (y > 265) {
      doc.addPage();
      y = 20;
    }
  }

  // ─ Page 2: VirusTotal + Network + APIs + Narrative ─

  if (p.virusTotal) {
    if (y > 220) {
      doc.addPage();
      y = 20;
    }
    y = sectionHeading(doc, "5. VIRUSTOTAL THREAT INTELLIGENCE", y, pageWidth);
    if (p.virusTotal.found && p.virusTotal.stats) {
      const { malicious, suspicious, undetected, harmless } = p.virusTotal.stats;
      const total = malicious + suspicious + undetected + harmless;
      const isBad = malicious > 0;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(isBad ? 220 : 5, isBad ? 38 : 150, isBad ? 38 : 105);
      doc.text(`Community Detection: ${malicious} / ${total} security vendors flagged this file.`, 14, y + 4);
      doc.setFont("courier", "normal");
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text(`Permalink: ${p.virusTotal.permalink}`, 14, y + 10);
      y += 16;
    } else {
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(100, 116, 139);
      doc.text("File hash not found in VirusTotal. Automatically submitted for baseline scanning.", 14, y + 4);
      y += 10;
    }
  }

  if (p.urls.length > 0 || p.ips.length > 0) {
    if (y > 200) {
      doc.addPage();
      y = 20;
    }
    y = sectionHeading(doc, "5. EMBEDDED NETWORK INDICATORS", y, pageWidth);
    doc.setFont("courier", "normal");
    doc.setFontSize(8);

    if (p.urls.length > 0) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text("URLs:", 14, y + 4);
      y += 8;
      p.urls.slice(0, 5).forEach((url) => {
        doc.setTextColor(100, 116, 139); // Changed from Red to Neutral Slate
        doc.setFont("courier", "normal");
        doc.setFontSize(7.5);
        doc.text(url.slice(0, 90), 18, y);
        y += 5;
      });
    }
    if (p.ips.length > 0) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.setTextColor(100, 116, 139);
      doc.text("IPs:", 14, y + 4);
      y += 8;
      p.ips.slice(0, 5).forEach((ip) => {
        doc.setTextColor(100, 116, 139); // Changed from Orange to Neutral Slate
        doc.setFont("courier", "normal");
        doc.setFontSize(7.5);
        doc.text(ip, 18, y);
        y += 5;
      });
    }
    y += 6;
  }

  // ─ Threat Narrative (always on fresh page if needed) ─
  
  if (y > 160) {
    doc.addPage();
    y = 20;
  }
  y = sectionHeading(doc, "6. AI THREAT NARRATIVE (NVIDIA NIM)", y, pageWidth);
  doc.setFont("courier", "normal");
  doc.setFontSize(8);
  doc.setTextColor(30, 41, 59);
  const narrativeLines = doc.splitTextToSize(p.threatNarrative, 182);
  const maxLines = 60;
  doc.text(narrativeLines.slice(0, maxLines), 14, y + 2);
  y += Math.min(narrativeLines.length, maxLines) * 4.5 + 10;

  if (y > 220) {
    doc.addPage();
    y = 20;
  }
  y = sectionHeading(doc, "METHODOLOGY & LEGAL DISCLAIMER", y, pageWidth);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  
  const disclaimerText = "METHODOLOGY: APK Sentinel performs static binary analysis on compiled Dalvik Executable (DEX) files and Android XML (AXML) manifests. The Risk Score (0-100) is calculated deterministically using a weighted heuristic engine that correlates requested permissions, embedded network indicators, signer integrity, and known malicious SDK footprints.\n\n" +
  "LEGAL DISCLAIMER: This automated threat report is generated strictly for informational and cybersecurity auditing purposes. The findings herein are derived from static analysis patterns and AI-driven interpretation, which may occasionally produce false positives or false negatives. This report does not constitute legally binding forensic evidence. APK Sentinel and its creators assume no liability for damages, loss of data, or operational disruptions resulting from actions taken based on this report. Users must perform independent verification before blacklisting or authorizing applications in enterprise environments.";
  
  const disclaimerLines = doc.splitTextToSize(disclaimerText, 182);
  doc.text(disclaimerLines, 14, y + 2);
  y += disclaimerLines.length * 3.5 + 10;

  // ─ Footer on last page ─

  const totalPages = (doc.internal as unknown as { getNumberOfPages: () => number }).getNumberOfPages?.() ?? 1;
  for (let pg = 1; pg <= totalPages; pg++) {
    doc.setPage(pg);
    doc.setFont("courier", "normal");
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `APK Sentinel • IIT-H Hackathon 2026 • CONFIDENTIAL SECURITY REPORT • Page ${pg}/${totalPages}`,
      14,
      doc.internal.pageSize.getHeight() - 8
    );
  }

  doc.save(`APK_Sentinel_Report_${p.fileName.replace(/[^a-zA-Z0-9]/g, "_")}.pdf`);
}
