import type { AnalysisFinding, AnalysisSeverity } from "./permissions";

export interface DetectedSdk {
  name: string;
  category: string;
  severity: AnalysisSeverity;
  matches: string[];
}

interface SdkRule {
  name: string;
  category: string;
  severity: AnalysisSeverity;
  patterns: string[];
  description: string;
}

const SDK_RULES: SdkRule[] = [
  {
    name: "DexClassLoader runtime loading",
    category: "Dynamic loading",
    severity: "HIGH",
    patterns: ["dalvik.system.DexClassLoader", "dalvik/system/DexClassLoader"],
    description: "Runtime DEX loading can execute code that was not visible during static review.",
  },
  {
    name: "Android Accessibility Service",
    category: "UI surveillance",
    severity: "CRITICAL",
    patterns: ["android.accessibilityservice.AccessibilityService", "android/accessibilityservice/AccessibilityService"],
    description: "Accessibility services can inspect screens and capture user interaction events.",
  },
  {
    name: "SMS Manager",
    category: "Telephony",
    severity: "HIGH",
    patterns: ["android.telephony.SmsManager", "android/telephony/SmsManager"],
    description: "SMS APIs can send or process messages outside expected UI flows.",
  },
  {
    name: "Runtime command execution",
    category: "System execution",
    severity: "HIGH",
    patterns: ["java.lang.Runtime", "java/lang/Runtime", "Runtime.exec"],
    description: "Runtime execution APIs can invoke shell commands or probe device state.",
  },
  {
    name: "Igexin Push SDK",
    category: "Ad/tracker SDK",
    severity: "MEDIUM",
    patterns: ["com.igexin.sdk", "com/igexin/sdk"],
    description: "Known aggressive push/advertising SDK detected in bytecode identifiers.",
  },
  {
    name: "AppsFlyer SDK",
    category: "Analytics SDK",
    severity: "LOW",
    patterns: ["com.appsflyer", "com/appsflyer"],
    description: "Commercial analytics SDK detected.",
  },
  {
    name: "Firebase SDK",
    category: "Cloud SDK",
    severity: "LOW",
    patterns: ["com.google.firebase", "com/google/firebase"],
    description: "Firebase SDK classes detected.",
  },
];

export function detectSdks(classNames: string[], strings: string[]): {
  sdks: DetectedSdk[];
  findings: AnalysisFinding[];
} {
  const searchSpace = [...classNames, ...strings];
  const sdks = SDK_RULES.map((rule) => {
    const matches = searchSpace
      .filter((value) => rule.patterns.some((pattern) => value.includes(pattern)))
      .slice(0, 8);
    return matches.length > 0
      ? {
          name: rule.name,
          category: rule.category,
          severity: rule.severity,
          matches,
        }
      : null;
  }).filter((sdk): sdk is DetectedSdk => Boolean(sdk));

  const findings = sdks
    .filter((sdk) => sdk.severity !== "LOW")
    .map((sdk, index) => {
      const rule = SDK_RULES.find((item) => item.name === sdk.name);
      return {
        id: `SDK-${String(index + 1).padStart(2, "0")}`,
        scope: "SDK" as const,
        severity: sdk.severity,
        title: sdk.name,
        description: rule?.description ?? `${sdk.category} indicator detected in class or string tables.`,
        evidence: sdk.matches,
      };
    });

  return { sdks, findings };
}
