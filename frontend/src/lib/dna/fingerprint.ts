// ===================================================================
// Session 5 — DNA Fingerprint Data Generator
// Converts APK analysis features into structured ring data for the
// DnaFingerprint canvas visualization.
// ===================================================================

export interface FingerprintRingSegment {
  angle: number;        // start angle in radians
  span: number;         // arc span in radians
  color: string;
  opacity: number;
  ring: "outer" | "middle" | "inner";
}

export interface FingerprintData {
  outerSegments: FingerprintRingSegment[];
  middleSegments: FingerprintRingSegment[];
  innerColor: string;
  coreColor: string;
  verdict: "BENIGN" | "SUSPICIOUS" | "FRAUDULENT" | "MALICIOUS";
  score: number;
}

interface FingerprintInput {
  score: number;
  verdict: "BENIGN" | "SUSPICIOUS" | "FRAUDULENT" | "MALICIOUS";
  permissionCount: number;
  criticalPermissions: number;
  suspiciousPermissions: number;
  highRiskApis: number;
  urlCount: number;
  ipCount: number;
  classCount: number;
  isDebuggable: boolean;
  debugKey: boolean;
}

const COLORS = {
  MALICIOUS:  { primary: "#dc2626", secondary: "#7c3aed", neutral: "#1e40af" },
  FRAUDULENT: { primary: "#ea580c", secondary: "#d97706", neutral: "#1e40af" },
  SUSPICIOUS: { primary: "#d97706", secondary: "#2563eb", neutral: "#64748b" },
  BENIGN:     { primary: "#059669", secondary: "#2563eb", neutral: "#64748b" },
};

export function generateFingerprint(input: FingerprintInput): FingerprintData {
  const { verdict, score, permissionCount, criticalPermissions, suspiciousPermissions, highRiskApis } = input;
  const colors = COLORS[verdict];
  const TAU = Math.PI * 2;

  // ── Outer ring: Method/class density (36 sectors) ────────────────
  const outerSegments: FingerprintRingSegment[] = [];
  const sectorCount = 36;
  for (let i = 0; i < sectorCount; i++) {
    const angle = (i * TAU) / sectorCount;
    const span  = (0.78 * TAU) / sectorCount;

    let color   = "rgba(148, 163, 184, 0.15)";
    let opacity = 0.2;

    if (score > 0) {
      const phase = (i / sectorCount) * TAU;
      const intensity = 0.5 + 0.5 * Math.sin(phase + i * 0.7);

      if (verdict === "MALICIOUS") {
        color   = i % 3 === 0 ? colors.primary : i % 5 === 0 ? colors.secondary : colors.neutral;
        opacity = 0.4 + intensity * 0.4;
      } else if (verdict === "FRAUDULENT") {
        color   = i % 2 === 0 ? colors.primary : colors.secondary;
        opacity = 0.35 + intensity * 0.35;
      } else if (verdict === "SUSPICIOUS") {
        color   = i % 4 === 0 ? colors.primary : colors.neutral;
        opacity = 0.25 + intensity * 0.25;
      } else {
        color   = colors.primary;
        opacity = 0.2 + intensity * 0.2;
      }
    }

    outerSegments.push({ angle, span, color, opacity, ring: "outer" });
  }

  // ── Middle ring: Permission heatmap ──────────────────────────────
  const middleSegments: FingerprintRingSegment[] = [];
  const permSectors = Math.max(4, permissionCount);
  for (let i = 0; i < permSectors; i++) {
    const angle = (i * TAU) / permSectors;
    const span  = (0.82 * TAU) / permSectors;

    let color   = "#059669";
    let opacity = 0.35;

    if (i < criticalPermissions) {
      color   = "#dc2626";
      opacity = 0.75;
    } else if (i < criticalPermissions + suspiciousPermissions) {
      color   = "#d97706";
      opacity = 0.55;
    }

    middleSegments.push({ angle, span, color, opacity, ring: "middle" });
  }

  // ── Inner ring and core ───────────────────────────────────────────
  const innerColor = colors.primary;
  const coreColor  = score > 70
    ? "rgba(220,38,38,0.4)"
    : score > 30
    ? "rgba(217,119,6,0.4)"
    : "rgba(5,150,105,0.4)";

  return { outerSegments, middleSegments, innerColor, coreColor, verdict, score };
}
