import type { ManifestInfo } from "@/lib/apk-parser/manifest-decoder";

export type AnalysisSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface AnalysisFinding {
  id: string;
  scope: "Permission" | "Repackaging" | "SDK" | "String" | "Manifest";
  severity: AnalysisSeverity;
  title: string;
  description: string;
  evidence: string[];
}

export interface PermissionAssessment {
  name: string;
  dangerous: boolean;
  severity: AnalysisSeverity;
  category: string;
  description: string;
}

interface PermissionRule {
  category: string;
  severity: AnalysisSeverity;
  description: string;
}

const PERMISSION_RULES: Record<string, PermissionRule> = {
  "android.permission.BIND_ACCESSIBILITY_SERVICE": {
    category: "UI capture",
    severity: "CRITICAL",
    description: "Can observe UI nodes, gestures, and typed input through an accessibility service.",
  },
  "android.permission.RECEIVE_SMS": {
    category: "SMS interception",
    severity: "CRITICAL",
    description: "Can read incoming SMS content, including one-time passcodes.",
  },
  "android.permission.SEND_SMS": {
    category: "SMS control",
    severity: "HIGH",
    description: "Can send SMS messages without a normal user workflow.",
  },
  "android.permission.SYSTEM_ALERT_WINDOW": {
    category: "Overlay",
    severity: "CRITICAL",
    description: "Can draw overlays above other applications and imitate login screens.",
  },
  "android.permission.READ_CONTACTS": {
    category: "Data access",
    severity: "MEDIUM",
    description: "Can access the device contact list.",
  },
  "android.permission.ACCESS_FINE_LOCATION": {
    category: "Location",
    severity: "MEDIUM",
    description: "Can collect precise location telemetry.",
  },
  "android.permission.RECORD_AUDIO": {
    category: "Sensor",
    severity: "HIGH",
    description: "Can capture microphone audio.",
  },
  "android.permission.CAMERA": {
    category: "Sensor",
    severity: "MEDIUM",
    description: "Can access camera hardware.",
  },
  "android.permission.READ_EXTERNAL_STORAGE": {
    category: "Storage",
    severity: "MEDIUM",
    description: "Can read shared external storage.",
  },
  "android.permission.WRITE_EXTERNAL_STORAGE": {
    category: "Storage",
    severity: "MEDIUM",
    description: "Can write shared external storage.",
  },
  "android.permission.REQUEST_INSTALL_PACKAGES": {
    category: "Installer",
    severity: "HIGH",
    description: "Can request installation of additional APK packages.",
  },
  "android.permission.RECEIVE_BOOT_COMPLETED": {
    category: "Persistence",
    severity: "MEDIUM",
    description: "Can restart app behavior after device boot.",
  },
  "android.permission.INTERNET": {
    category: "Network",
    severity: "LOW",
    description: "Can initiate outbound network traffic.",
  },
};

const DANGEROUS_COMBOS = [
  {
    id: "PERM-COMBO-01",
    title: "Overlay phishing capability",
    permissions: ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"],
    severity: "CRITICAL" as const,
    description: "Overlay permission combined with networking can support credential phishing and exfiltration.",
  },
  {
    id: "PERM-COMBO-02",
    title: "SMS takeover capability",
    permissions: ["android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"],
    severity: "CRITICAL" as const,
    description: "Bidirectional SMS access can intercept OTPs and send premium or fraud messages.",
  },
  {
    id: "PERM-COMBO-03",
    title: "Persistent dropper capability",
    permissions: ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.REQUEST_INSTALL_PACKAGES"],
    severity: "HIGH" as const,
    description: "Boot persistence combined with package installation can support secondary payload deployment.",
  },
];

export function analyzePermissions(manifest: ManifestInfo): {
  permissions: PermissionAssessment[];
  findings: AnalysisFinding[];
} {
  const permissions = manifest.permissions.map((name) => {
    const rule = PERMISSION_RULES[name];
    return {
      name,
      dangerous: Boolean(rule && rule.severity !== "LOW"),
      severity: rule?.severity ?? "LOW",
      category: rule?.category ?? "Declared",
      description: rule?.description ?? "Declared manifest permission extracted from AndroidManifest.xml.",
    };
  });

  const findings: AnalysisFinding[] = permissions
    .filter((permission) => permission.dangerous)
    .map((permission, index) => ({
      id: `PERM-${String(index + 1).padStart(2, "0")}`,
      scope: "Permission",
      severity: permission.severity,
      title: `${permission.category}: ${permission.name.replace("android.permission.", "")}`,
      description: permission.description,
      evidence: [permission.name],
    }));

  const permissionSet = new Set(manifest.permissions);
  for (const combo of DANGEROUS_COMBOS) {
    if (combo.permissions.every((permission) => permissionSet.has(permission))) {
      findings.push({
        id: combo.id,
        scope: "Permission",
        severity: combo.severity,
        title: combo.title,
        description: combo.description,
        evidence: combo.permissions,
      });
    }
  }

  if (manifest.isDebuggable) {
    findings.push({
      id: "MANIFEST-DEBUG",
      scope: "Manifest",
      severity: "MEDIUM",
      title: "Debuggable application build",
      description: "The manifest enables android:debuggable, which weakens production hardening.",
      evidence: ["android:debuggable=true"],
    });
  }

  if (manifest.allowBackup) {
    findings.push({
      id: "MANIFEST-BACKUP",
      scope: "Manifest",
      severity: "LOW",
      title: "Application backup is enabled",
      description: "The manifest allows backup extraction, which can expose local app data on compromised devices.",
      evidence: ["android:allowBackup=true"],
    });
  }

  return { permissions, findings };
}
