import type { AnalysisFinding } from "./permissions";

export interface StringIndicators {
  urls: string[];
  ips: string[];
  suspiciousStrings: string[];
  findings: AnalysisFinding[];
}

const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>\\)]+/gi;
const IP_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const SECRET_PATTERNS = [
  /api[_-]?key/i,
  /secret[_-]?key/i,
  /access[_-]?token/i,
  /bearer\s+[a-z0-9._-]{16,}/i,
  /password\s*=/i,
];
const SUSPICIOUS_DOMAIN_TOKENS = [
  "c2",
  "payload",
  "drop",
  "phish",
  "bot",
  "exfil",
  "token",
  "gate",
];

export function analyzeStrings(strings: string[]): StringIndicators {
  const urls = unique(strings.flatMap((value) => value.match(URL_PATTERN) ?? [])).slice(0, 100);
  const ips = unique(strings.flatMap((value) => value.match(IP_PATTERN) ?? [])).slice(0, 100);
  const suspiciousStrings = unique(
    strings.filter((value) => SECRET_PATTERNS.some((pattern) => pattern.test(value)))
  ).slice(0, 40);

  const findings: AnalysisFinding[] = [];

  const suspiciousUrls = urls.filter((url) => {
    const lower = url.toLowerCase();
    return SUSPICIOUS_DOMAIN_TOKENS.some((token) => lower.includes(token)) || lower.startsWith("http://");
  });

  if (urls.length > 0) {
    findings.push({
      id: "STR-URLS",
      scope: "String",
      severity: suspiciousUrls.length > 0 ? "HIGH" : "LOW",
      title: suspiciousUrls.length > 0 ? "Suspicious outbound URL indicators" : "Outbound URL indicators",
      description: suspiciousUrls.length > 0
        ? "DEX strings include URLs with suspicious tokens or cleartext HTTP endpoints."
        : "DEX strings include outbound URL endpoints for network communication.",
      evidence: (suspiciousUrls.length > 0 ? suspiciousUrls : urls).slice(0, 8),
    });
  }

  if (ips.length > 0) {
    findings.push({
      id: "STR-IPS",
      scope: "String",
      severity: "MEDIUM",
      title: "Raw IP address indicators",
      description: "DEX strings contain raw IP addresses, which can indicate hardcoded backend or command-and-control endpoints.",
      evidence: ips.slice(0, 8),
    });
  }

  if (suspiciousStrings.length > 0) {
    findings.push({
      id: "STR-SECRETS",
      scope: "String",
      severity: "HIGH",
      title: "Hardcoded secret-like strings",
      description: "String tables contain token, key, or password-like literals.",
      evidence: suspiciousStrings.slice(0, 8),
    });
  }

  return { urls, ips, suspiciousStrings, findings };
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}
