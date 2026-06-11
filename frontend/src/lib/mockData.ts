import { MinimalProfileData } from "./ai/nvidia-client";

export const MOCK_PROFILES: Record<string, MinimalProfileData> = {
  "BankBot": {
    packageName: "com.secure.banking.update",
    fileName: "BankBot_Update_v2.apk",
    verdict: "MALICIOUS",
    score: 94,
    permissions: [
      { name: "android.permission.INTERNET", dangerous: false },
      { name: "android.permission.RECEIVE_BOOT_COMPLETED", dangerous: false },
      { name: "android.permission.BIND_ACCESSIBILITY_SERVICE", dangerous: true },
      { name: "android.permission.SYSTEM_ALERT_WINDOW", dangerous: true },
      { name: "android.permission.READ_SMS", dangerous: true },
      { name: "android.permission.RECEIVE_SMS", dangerous: true }
    ],
    urls: ["http://c2-malicious-domain.ru/gate.php"],
    ips: ["185.199.108.153"],
    apis: [{ name: "dalvik.system.DexClassLoader" }, { name: "android.telephony.SmsManager" }],
    keyFindings: [
      { severity: "CRITICAL", scope: "Permissions", label: "Accessibility Service Hijack", details: "App binds BIND_ACCESSIBILITY_SERVICE to capture screen contents." },
      { severity: "HIGH", scope: "Code", label: "Overlay Attack", details: "Uses SYSTEM_ALERT_WINDOW to draw over other apps (phishing)." }
    ],
    classCount: 1250,
    stringCount: 4500
  },
  "Adware": {
    packageName: "com.free.games.sudoku",
    fileName: "Sudoku_Free_Ads.apk",
    verdict: "SUSPICIOUS",
    score: 45,
    permissions: [
      { name: "android.permission.INTERNET", dangerous: false },
      { name: "android.permission.ACCESS_FINE_LOCATION", dangerous: true },
      { name: "android.permission.ACCESS_WIFI_STATE", dangerous: false }
    ],
    urls: ["https://ad.tracking-network.com/serve"],
    ips: [],
    apis: [{ name: "android.location.LocationManager" }],
    keyFindings: [
      { severity: "MEDIUM", scope: "Privacy", label: "Aggressive Tracking", details: "Collects precise location data heavily in the background." }
    ],
    classCount: 300,
    stringCount: 1200
  },
  "CryptoWallet": {
    packageName: "com.crypto.wallet.official",
    fileName: "CryptoWallet_Mod.apk",
    verdict: "FRAUDULENT",
    score: 78,
    permissions: [
      { name: "android.permission.INTERNET", dangerous: false },
      { name: "android.permission.CAMERA", dangerous: true },
      { name: "android.permission.READ_EXTERNAL_STORAGE", dangerous: true }
    ],
    urls: ["https://pastebin.com/raw/xyz"],
    ips: ["103.45.67.89"],
    apis: [{ name: "javax.crypto.Cipher" }],
    keyFindings: [
      { severity: "HIGH", scope: "Repackaging", label: "Signature Mismatch", details: "Application signature does not match the official developer." },
      { severity: "HIGH", scope: "Code", label: "Suspicious Endpoint", details: "Connects to a pastebin URL known to host secondary payloads." }
    ],
    classCount: 4500,
    stringCount: 8900
  },
  "Calculator": {
    packageName: "com.simple.calculator",
    fileName: "CalcApp.apk",
    verdict: "BENIGN",
    score: 5,
    permissions: [],
    urls: [],
    ips: [],
    apis: [],
    keyFindings: [],
    classCount: 45,
    stringCount: 150
  }
};

export const INITIAL_LEDGER_ROWS = [
  { id: "REP-2026-001", file: MOCK_PROFILES["BankBot"].fileName, date: "2026-06-11", verdict: "MALICIOUS", profileKey: "BankBot" },
  { id: "REP-2026-002", file: MOCK_PROFILES["Adware"].fileName, date: "2026-06-10", verdict: "SUSPICIOUS", profileKey: "Adware" },
  { id: "REP-2026-003", file: MOCK_PROFILES["CryptoWallet"].fileName, date: "2026-06-09", verdict: "FRAUDULENT", profileKey: "CryptoWallet" },
  { id: "REP-2026-004", file: MOCK_PROFILES["Calculator"].fileName, date: "2026-06-08", verdict: "BENIGN", profileKey: "Calculator" }
];
