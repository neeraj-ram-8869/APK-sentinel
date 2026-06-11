import type { ApkSignatureInfo } from "@/lib/apk-parser/signature";
import type { ManifestInfo } from "@/lib/apk-parser/manifest-decoder";
import type { AnalysisFinding } from "./permissions";

interface KnownAppProfile {
  packageName: string;
  appName: string;
  trustedSignerTokens: string[];
}

const KNOWN_APPS: KnownAppProfile[] = [
  {
    packageName: "com.whatsapp",
    appName: "WhatsApp Messenger",
    trustedSignerTokens: ["WhatsApp", "Meta", "Facebook"],
  },
  {
    packageName: "com.paypal.android.p2pmobile",
    appName: "PayPal",
    trustedSignerTokens: ["PayPal"],
  },
  {
    packageName: "com.citibank.mobile.pay",
    appName: "Citibank Mobile Pay",
    trustedSignerTokens: ["Citibank", "Citi"],
  },
  {
    packageName: "com.chase.sig.banking",
    appName: "Chase Mobile Banking",
    trustedSignerTokens: ["JPMorgan", "Chase"],
  },
];

export function detectRepackaging(
  manifest: ManifestInfo,
  signature: ApkSignatureInfo,
  strings: string[]
): AnalysisFinding[] {
  const findings: AnalysisFinding[] = [];
  const knownApp = KNOWN_APPS.find((app) => app.packageName === manifest.packageName);
  const signerText = `${signature.signerSummary} ${signature.fingerprintSha256 ?? ""}`;

  if (knownApp) {
    const signerMatches = knownApp.trustedSignerTokens.some((token) =>
      signerText.toLowerCase().includes(token.toLowerCase())
    );

    if (!signerMatches || signature.debugKey || signature.status !== "TRUSTED") {
      findings.push({
        id: "REPACK-01",
        scope: "Repackaging",
        severity: "CRITICAL",
        title: `${knownApp.appName} signer mismatch`,
        description: "The package identifier matches a known financial or communication app, but signer metadata does not match the expected developer identity.",
        evidence: [
          `package=${manifest.packageName}`,
          `signer=${signature.signerSummary}`,
          `status=${signature.status}`,
        ],
      });
    }
  }

  const brandMentions = KNOWN_APPS
    .filter((app) => app.packageName !== manifest.packageName)
    .filter((app) => strings.some((value) => value.toLowerCase().includes(app.appName.toLowerCase().split(" ")[0])))
    .slice(0, 3);

  for (const app of brandMentions) {
    findings.push({
      id: `REPACK-BRAND-${app.packageName}`,
      scope: "Repackaging",
      severity: "MEDIUM",
      title: `Possible brand impersonation: ${app.appName}`,
      description: "DEX strings mention a known app brand while the package identifier belongs to a different application.",
      evidence: [`package=${manifest.packageName}`, `brand=${app.appName}`],
    });
  }

  if (signature.debugKey) {
    findings.push({
      id: "REPACK-DEBUG-SIGNER",
      scope: "Repackaging",
      severity: "HIGH",
      title: "Debug certificate used for signed APK",
      description: "Production APKs signed with Android debug keys are commonly associated with repackaged or test builds.",
      evidence: [signature.signerSummary],
    });
  }

  if (signature.certificateFiles.length === 0) {
    findings.push({
      id: "REPACK-NO-CERT",
      scope: "Repackaging",
      severity: "HIGH",
      title: "Missing META-INF certificate container",
      description: "No APK signing certificate container was found in META-INF, preventing normal signer trust checks.",
      evidence: ["META-INF certificate container missing"],
    });
  }

  return findings;
}
