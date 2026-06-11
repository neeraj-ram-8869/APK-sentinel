"use client";

// ===================================================================
// Session 6 — RepackagingBadge Component
// Compact indicator shown in the dashboard header when repackaging
// or signer mismatch is detected.
// ===================================================================

interface RepackagingBadgeProps {
  verdict: "BENIGN" | "SUSPICIOUS" | "FRAUDULENT" | "MALICIOUS";
  isDebugKey: boolean;
  isSelfSigned: boolean;
  certStatus: "TRUSTED" | "WARNING" | "UNTRUSTED";
  packageName: string;
  score: number;
}

const KNOWN_BRAND_TOKENS = [
  "whatsapp", "paypal", "citibank", "chase", "bankofamerica",
  "amazon", "google", "facebook", "instagram", "tiktok",
];

export default function RepackagingBadge({
  verdict,
  isDebugKey,
  isSelfSigned,
  certStatus,
  packageName,
  score,
}: RepackagingBadgeProps) {
  const pkgLower = packageName.toLowerCase();
  const brandMatch = KNOWN_BRAND_TOKENS.find((token) => pkgLower.includes(token));
  const isSuspectClone = Boolean(brandMatch) && certStatus !== "TRUSTED";
  const hasSigningRisk = isDebugKey || isSelfSigned || certStatus === "UNTRUSTED";

  if (!isSuspectClone && !hasSigningRisk && verdict === "BENIGN") return null;

  const badges: Array<{ label: string; color: string; bg: string; icon: string }> = [];

  if (isSuspectClone) {
    badges.push({
      label: `Clone / Repackage (${brandMatch})`,
      color: "#dc2626",
      bg: "rgba(220,38,38,0.08)",
      icon: "⚠",
    });
  }
  if (isDebugKey) {
    badges.push({
      label: "Debug Signing Key",
      color: "#dc2626",
      bg: "rgba(220,38,38,0.08)",
      icon: "🔓",
    });
  } else if (isSelfSigned) {
    badges.push({
      label: "Self-Signed Certificate",
      color: "#d97706",
      bg: "rgba(217,119,6,0.08)",
      icon: "🔐",
    });
  }
  if (certStatus === "UNTRUSTED" && !isDebugKey) {
    badges.push({
      label: "Untrusted Signer",
      color: "#d97706",
      bg: "rgba(217,119,6,0.08)",
      icon: "⚠",
    });
  }

  return (
    <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
      {badges.map((badge, i) => (
        <div
          key={i}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "5px",
            background: badge.bg,
            color: badge.color,
            border: `1px solid ${badge.color}40`,
            borderRadius: "4px",
            padding: "3px 10px",
            fontSize: "0.7rem",
            fontWeight: 800,
            letterSpacing: "0.02em",
          }}
        >
          <span>{badge.icon}</span>
          <span>{badge.label}</span>
        </div>
      ))}
    </div>
  );
}
