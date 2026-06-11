// ===================================================================
// Session 5 — Rule-based Risk Scoring Engine with Explainability
//
// Each rule contributes a named weight to the total score so the UI
// can explain "why" an APK received its verdict rather than just
// returning a number.
// ===================================================================

export type ScoringTier = "BENIGN" | "SUSPICIOUS" | "FRAUDULENT" | "MALICIOUS";

export interface ScoreContribution {
  id: string;
  label: string;
  category: "Permission" | "Certificate" | "Network" | "SDK" | "Manifest" | "Finding";
  weight: number;        // points added to total
  evidence: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface ScoringResult {
  score: number;         // 0–100
  tier: ScoringTier;
  confidence: string;    // e.g. "92%"
  contributions: ScoreContribution[];
  topRisk: string;       // single sentence summary
}

// ===========================
// Inputs accepted by scorer
// ===========================

export interface ScoringInput {
  permissions: string[];
  isDebuggable: boolean;
  allowBackup: boolean;
  exportedComponents: number;
  urls: string[];
  ips: string[];
  classNames: string[];
  allStrings: string[];
  certDebugKey: boolean;
  certStatus: "TRUSTED" | "WARNING" | "UNTRUSTED";
  findings: Array<{
    id: string;
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    scope: string;
    title: string;
  }>;
  vtFound?: boolean;
  vtMalicious?: number;
  policyOverrides?: {
    sysAlert?: number;
    sms?: number;
    dex?: number;
    cert?: number;
  };
}

// ===========================
// Permission weight table
// ===========================

const PERMISSION_WEIGHTS: Record<string, { label: string; weight: number; severity: ScoreContribution["severity"] }> = {
  "android.permission.BIND_ACCESSIBILITY_SERVICE": { label: "Accessibility service (keylogger risk)", weight: 22, severity: "CRITICAL" },
  "android.permission.SYSTEM_ALERT_WINDOW":         { label: "Overlay drawing (phishing risk)",       weight: 20, severity: "CRITICAL" },
  "android.permission.RECEIVE_SMS":                 { label: "SMS intercept (2FA bypass)",             weight: 18, severity: "CRITICAL" },
  "android.permission.SEND_SMS":                    { label: "SMS transmission",                        weight: 12, severity: "HIGH"     },
  "android.permission.REQUEST_INSTALL_PACKAGES":    { label: "Package installer (dropper risk)",        weight: 12, severity: "HIGH"     },
  "android.permission.RECORD_AUDIO":                { label: "Microphone access",                       weight: 2,  severity: "LOW"      },
  "android.permission.RECEIVE_BOOT_COMPLETED":      { label: "Boot persistence",                        weight: 4,  severity: "LOW"      },
  "android.permission.ACCESS_FINE_LOCATION":        { label: "Precise location tracking",               weight: 2,  severity: "LOW"      },
  "android.permission.READ_CONTACTS":               { label: "Contact list access",                     weight: 2,  severity: "LOW"      },
  "android.permission.CAMERA":                      { label: "Camera access",                           weight: 2,  severity: "LOW"      },
  "android.permission.READ_EXTERNAL_STORAGE":       { label: "External storage read",                   weight: 1,  severity: "LOW"      },
  "android.permission.WRITE_EXTERNAL_STORAGE":      { label: "External storage write",                  weight: 1,  severity: "LOW"      },
};

const DANGEROUS_COMBOS: Array<{
  id: string;
  permissions: string[];
  label: string;
  weight: number;
  severity: ScoreContribution["severity"];
}> = [
  {
    id: "COMBO-PHISH",
    permissions: ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"],
    label: "Overlay + network: phishing capability",
    weight: 15,
    severity: "CRITICAL",
  },
  {
    id: "COMBO-SMS",
    permissions: ["android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"],
    label: "Bidirectional SMS: OTP interception + fraud SMS",
    weight: 14,
    severity: "CRITICAL",
  },
  {
    id: "COMBO-PERSIST",
    permissions: ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.REQUEST_INSTALL_PACKAGES"],
    label: "Boot persistence + dropper: secondary payload risk",
    weight: 10,
    severity: "HIGH",
  },
];

// ===========================
// SDK patterns
// ===========================

const HIGH_RISK_PATTERNS: Array<{ token: string; label: string; weight: number }> = [
  { token: "dalvik.system.DexClassLoader",                           label: "DexClassLoader: runtime code loading",          weight: 12 },
  { token: "android.accessibilityservice.AccessibilityService",      label: "AccessibilityService: UI surveillance",         weight: 18 },
  { token: "android.telephony.SmsManager",                           label: "SmsManager API in DEX",                         weight: 10 },
  { token: "java.lang.Runtime",                                       label: "Runtime.exec: shell command execution",         weight: 10 },
  { token: "com.igexin.sdk",                                          label: "Igexin aggressive tracker SDK",                 weight: 6  },
];

// ===========================
// Score calculation
// ===========================

export function calculateScore(input: ScoringInput): ScoringResult {
  const contributions: ScoreContribution[] = [];
  const permSet = new Set(input.permissions);

  // ── 1. Individual permissions ─────────────────────────────────────
  for (const [perm, rule] of Object.entries(PERMISSION_WEIGHTS)) {
    if (permSet.has(perm)) {
      let activeWeight = rule.weight;
      if (perm === "android.permission.SYSTEM_ALERT_WINDOW" && input.policyOverrides?.sysAlert !== undefined) {
        activeWeight = input.policyOverrides.sysAlert;
      }
      if (perm === "android.permission.RECEIVE_SMS" && input.policyOverrides?.sms !== undefined) {
        activeWeight = input.policyOverrides.sms;
      }
      
      contributions.push({
        id: `PERM:${perm}`,
        label: rule.label,
        category: "Permission",
        weight: activeWeight,
        evidence: perm,
        severity: rule.severity,
      });
    }
  }

  // ── 2. Dangerous combos ───────────────────────────────────────────
  for (const combo of DANGEROUS_COMBOS) {
    if (combo.permissions.every((p) => permSet.has(p))) {
      contributions.push({
        id: combo.id,
        label: combo.label,
        category: "Permission",
        weight: combo.weight,
        evidence: combo.permissions.join(" + "),
        severity: combo.severity,
      });
    }
  }

  // ── 3. Certificate ────────────────────────────────────────────────
  let debugCertWeight = 15;
  let untrustedCertWeight = 8;
  if (input.policyOverrides?.cert !== undefined) {
    debugCertWeight = input.policyOverrides.cert;
    untrustedCertWeight = Math.floor(input.policyOverrides.cert * 0.5);
  }

  if (input.certDebugKey) {
    contributions.push({
      id: "CERT-DEBUG",
      label: "Debug signing key (non-production)",
      category: "Certificate",
      weight: debugCertWeight,
      evidence: "META-INF cert: debug key",
      severity: "HIGH",
    });
  }
  if (input.certStatus === "UNTRUSTED") {
    contributions.push({
      id: "CERT-UNTRUSTED",
      label: "Untrusted certificate",
      category: "Certificate",
      weight: untrustedCertWeight,
      evidence: "Certificate status: UNTRUSTED",
      severity: "HIGH",
    });
  } else if (input.certStatus === "WARNING") {
    contributions.push({
      id: "CERT-WARNING",
      label: "Certificate with warnings",
      category: "Certificate",
      weight: 4,
      evidence: "Certificate status: WARNING",
      severity: "MEDIUM",
    });
  }

  // ── 4. Network indicators ─────────────────────────────────────────
  const suspiciousUrls = input.urls.filter((u) =>
    /c2|payload|drop|phish|exfil|gate|bot|token/.test(u.toLowerCase())
  );
  if (suspiciousUrls.length > 0) {
    contributions.push({
      id: "NET-SUSPICIOUS-URLS",
      label: `${suspiciousUrls.length} suspicious URL(s) in DEX strings`,
      category: "Network",
      weight: Math.min(14, suspiciousUrls.length * 4 + 6),
      evidence: suspiciousUrls.slice(0, 2).join(", "),
      severity: "HIGH",
    });
  } else if (input.urls.length > 0) {
    contributions.push({
      id: "NET-URLS",
      label: `${input.urls.length} URL(s) embedded in DEX strings`,
      category: "Network",
      weight: Math.min(6, input.urls.length * 2),
      evidence: input.urls.slice(0, 2).join(", "),
      severity: "LOW",
    });
  }
  if (input.ips.length > 0) {
    contributions.push({
      id: "NET-IPS",
      label: `${input.ips.length} raw IP(s) in DEX strings`,
      category: "Network",
      weight: Math.min(10, input.ips.length * 4 + 2),
      evidence: input.ips.slice(0, 2).join(", "),
      severity: "MEDIUM",
    });
  }

  // ── 5. SDK/class-name patterns ────────────────────────────────────
  const searchSpace = [...input.classNames, ...input.allStrings.slice(0, 2000)];
  for (const pat of HIGH_RISK_PATTERNS) {
    const hit = searchSpace.some((s) => s.includes(pat.token));
    if (hit) {
      let activeWeight = pat.weight;
      if (pat.token === "dalvik.system.DexClassLoader" && input.policyOverrides?.dex !== undefined) {
        activeWeight = input.policyOverrides.dex;
      }
      
      contributions.push({
        id: `SDK:${pat.token}`,
        label: pat.label,
        category: "SDK",
        weight: activeWeight,
        evidence: pat.token,
        severity: activeWeight >= 12 ? "HIGH" : "MEDIUM",
      });
    }
  }

  // ── 6. Manifest flags ─────────────────────────────────────────────
  if (input.isDebuggable) {
    contributions.push({
      id: "MANIFEST-DEBUG",
      label: "android:debuggable=true",
      category: "Manifest",
      weight: 10,
      evidence: "Manifest flag: debuggable",
      severity: "MEDIUM",
    });
  }
  if (input.exportedComponents > 3) {
    contributions.push({
      id: "MANIFEST-EXPORT",
      label: `${input.exportedComponents} exported components (attack surface)`,
      category: "Manifest",
      weight: Math.min(8, input.exportedComponents * 2),
      evidence: `Exported components: ${input.exportedComponents}`,
      severity: "MEDIUM",
    });
  }

  // ── 7. Analyzer findings ──────────────────────────────────────────
  for (const finding of input.findings) {
    if (finding.severity === "CRITICAL") {
      contributions.push({
        id: `FINDING:${finding.id}`,
        label: `[${finding.scope}] ${finding.title}`,
        category: "Finding",
        weight: 12,
        evidence: finding.id,
        severity: "CRITICAL",
      });
    } else if (finding.severity === "HIGH") {
      contributions.push({
        id: `FINDING:${finding.id}`,
        label: `[${finding.scope}] ${finding.title}`,
        category: "Finding",
        weight: 7,
        evidence: finding.id,
        severity: "HIGH",
      });
    }
  }

  // ── 8. VirusTotal Intelligence ────────────────────────────────────
  if (input.vtFound) {
    if (input.vtMalicious === 0) {
      contributions.push({
        id: "VT-CLEAN",
        label: "VirusTotal Community: 0 Detections",
        category: "Network",
        weight: -50, // Massive reduction for verified clean apps
        evidence: "0 malicious engines out of 60+",
        severity: "LOW",
      });
    } else if ((input.vtMalicious ?? 0) > 0) {
      contributions.push({
        id: "VT-MALICIOUS",
        label: `VirusTotal Community: ${input.vtMalicious} Detections`,
        category: "Network",
        weight: Math.min(50, input.vtMalicious! * 10), // Massive penalty
        evidence: `${input.vtMalicious} malicious engines`,
        severity: "CRITICAL",
      });
    }
  }

  // ── Deduplicate by id, keep highest weight ─────────────────────────
  const deduped = new Map<string, ScoreContribution>();
  for (const c of contributions) {
    const existing = deduped.get(c.id);
    if (!existing || c.weight > existing.weight || c.weight < 0) deduped.set(c.id, c);
  }
  const finalContributions = [...deduped.values()].sort((a, b) => b.weight - a.weight);

  // ── Cap score at 100, min 0 ────────────────────────────────────────
  let raw = finalContributions.reduce((sum, c) => sum + c.weight, 0);
  
  // HARD CAP FOR VERIFIED COMMERCIAL APPS
  // Commercial apps (PhonePe, WhatsApp) request dozens of dangerous permissions natively.
  // If the app has 0 VirusTotal detections, the community consensus is that it's safe.
  // We mathematically crush the risk score to 10 (BENIGN) to prevent heuristic false positives.
  if (input.vtFound && input.vtMalicious === 0) {
    raw = Math.min(raw, 10);
  }

  const score = Math.max(0, Math.min(100, raw));

  const tier: ScoringTier =
    score >= 80 ? "MALICIOUS"
    : score >= 50 ? "FRAUDULENT"
    : score >= 20 ? "SUSPICIOUS"
    : "BENIGN";

  // Confidence: higher when more contributing signals present
  const signalCount = finalContributions.length;
  const confidence = `${Math.min(99, 60 + signalCount * 4 + Math.round(score / 10))}%`;

  // Top risk: highest-weight contribution
  const topContrib = finalContributions[0];
  const topRisk = topContrib
    ? `Primary risk driver: ${topContrib.label} (+${topContrib.weight} pts)`
    : "No significant risk factors detected.";

  return { score, tier, confidence, contributions: finalContributions, topRisk };
}
