import { useCallback, useState } from "react";
import { parseApk, type ApkParseProgress, type ApkParseResult } from "@/lib/apk-parser";
import { analyzePermissions, type AnalysisFinding, type PermissionAssessment } from "@/lib/analysis/permissions";
import { detectRepackaging } from "@/lib/analysis/repackaging";
import { detectSdks, type DetectedSdk } from "@/lib/analysis/sdk-detector";
import { analyzeStrings } from "@/lib/analysis/strings";

export interface AnalysisEvent extends ApkParseProgress {
  level: "info" | "success" | "warning" | "error";
}

export interface ApkAnalysisReport {
  permissions: PermissionAssessment[];
  sdks: DetectedSdk[];
  urls: string[];
  ips: string[];
  suspiciousStrings: string[];
  findings: AnalysisFinding[];
  virusTotal?: {
    found: boolean;
    stats?: { malicious: number; suspicious: number; undetected: number; harmless: number };
    permalink?: string;
  };
}

export interface AnalyzedApkResult extends ApkParseResult {
  analysis: ApkAnalysisReport;
}

export function useAnalysis() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const analyzeFile = useCallback(
    async (file: File, onEvent?: (event: AnalysisEvent) => void): Promise<AnalyzedApkResult> => {
      setIsAnalyzing(true);
      try {
        const parsed = await parseApk(file, (event) => {
          onEvent?.({
            ...event,
            level: inferLevel(event.message),
          });
        });

        emitAnalysisEvent(onEvent, 100, "INFO: Running Session 3 structured analysis engine");
        const analysis = runStructuredAnalysis(parsed);

        emitAnalysisEvent(onEvent, 100, "INFO: Querying VirusTotal Threat Intelligence");
        try {
          const vtRes = await fetch(`/api/virustotal?hash=${parsed.fileHash}`);
          if (vtRes.status === 404) {
            emitAnalysisEvent(onEvent, 100, "WARN: File unknown to VirusTotal. Uploading for analysis...");
            const formData = new FormData();
            formData.append("file", file);
            await fetch("/api/virustotal", { method: "POST", body: formData });
            analysis.virusTotal = { found: false };
            emitAnalysisEvent(onEvent, 100, "INFO: File uploaded to VirusTotal successfully");
          } else if (vtRes.ok) {
            const vtData = await vtRes.json();
            analysis.virusTotal = vtData;
            emitAnalysisEvent(onEvent, 100, `SUCCESS: VirusTotal report found (${vtData.stats?.malicious || 0} detections)`);
          }
        } catch (err) {
          emitAnalysisEvent(onEvent, 100, "ERROR: VirusTotal integration failed");
        }

        if (analysis.findings.length === 0) {
          emitAnalysisEvent(onEvent, 100, "SUCCESS: No categorized threat findings generated");
        } else {
          for (const finding of analysis.findings) {
            emitAnalysisEvent(
              onEvent,
              100,
              `${finding.severity === "LOW" ? "INFO" : finding.severity === "MEDIUM" ? "WARN" : "ERROR"}: FINDING [${finding.severity}] ${finding.scope} :: ${finding.title}`
            );
          }
        }

        emitAnalysisEvent(onEvent, 100, `SUCCESS: Analysis engine emitted ${analysis.findings.length} categorized finding(s)`);
        return { ...parsed, analysis };
      } finally {
        setIsAnalyzing(false);
      }
    },
    []
  );

  return { analyzeFile, isAnalyzing };
}

function runStructuredAnalysis(parsed: ApkParseResult): ApkAnalysisReport {
  const permissionAnalysis = analyzePermissions(parsed.manifest);
  const sdkAnalysis = detectSdks(parsed.classNames, parsed.allStrings);
  const stringAnalysis = analyzeStrings(parsed.allStrings);
  const repackagingFindings = detectRepackaging(parsed.manifest, parsed.signature, parsed.allStrings);

  const findings = [
    ...permissionAnalysis.findings,
    ...repackagingFindings,
    ...sdkAnalysis.findings,
    ...stringAnalysis.findings,
  ].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  return {
    permissions: permissionAnalysis.permissions,
    sdks: sdkAnalysis.sdks,
    urls: stringAnalysis.urls,
    ips: stringAnalysis.ips,
    suspiciousStrings: stringAnalysis.suspiciousStrings,
    findings,
  };
}

function inferLevel(message: string): AnalysisEvent["level"] {
  if (message.startsWith("SUCCESS")) return "success";
  if (message.startsWith("WARN")) return "warning";
  if (message.startsWith("ERROR")) return "error";
  return "info";
}

function emitAnalysisEvent(
  onEvent: ((event: AnalysisEvent) => void) | undefined,
  pct: number,
  message: string
): void {
  onEvent?.({
    pct,
    message,
    level: inferLevel(message),
  });
}

function severityRank(severity: AnalysisFinding["severity"]): number {
  if (severity === "CRITICAL") return 4;
  if (severity === "HIGH") return 3;
  if (severity === "MEDIUM") return 2;
  return 1;
}
