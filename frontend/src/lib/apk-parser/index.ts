import JSZip from "jszip";
import { decodeManifest, type ManifestInfo } from "./manifest-decoder";
import { findIpAddresses, findUrls, parseDex, type DexParseResult } from "./dex-parser";
import { parseSignature, type ApkSignatureInfo } from "./signature";

export interface ApkParseProgress {
  pct: number;
  message: string;
}

export interface ApkParseResult {
  fileName: string;
  fileSize: number;
  fileHash: string;
  manifest: ManifestInfo;
  dexFiles: DexParseResult[];
  signature: ApkSignatureInfo;
  urls: string[];
  ips: string[];
  allStrings: string[];
  classNames: string[];
  entries: string[];
}

export async function parseApk(
  file: File,
  onProgress?: (event: ApkParseProgress) => void
): Promise<ApkParseResult> {
  emit(onProgress, 2, `INFO: Computing SHA-256 hash of ${file.name}`);
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const fileHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  emit(onProgress, 5, `INFO: Hash computed: ${fileHash.slice(0, 16)}...`);

  const zip = await JSZip.loadAsync(arrayBuffer);
  const entries = Object.keys(zip.files).sort();
  emit(onProgress, 18, `INFO: ZIP central directory parsed (${entries.length} entries)`);

  const manifestFile = zip.file("AndroidManifest.xml");
  if (!manifestFile) {
    throw new Error("AndroidManifest.xml was not found in the APK archive.");
  }

  emit(onProgress, 30, "INFO: Decoding AndroidManifest.xml binary AXML");
  const manifest = decodeManifest(await manifestFile.async("arraybuffer"));
  if (manifest.error) {
    emit(onProgress, 34, `WARN: Manifest decoder fallback reported: ${manifest.error}`);
  }
  emit(onProgress, 42, `SUCCESS: Manifest package=${manifest.packageName || "unknown"} permissions=${manifest.permissions.length}`);

  const dexEntries = entries.filter((name) => /^classes(?:\d*)\.dex$/i.test(name));
  emit(onProgress, 52, `INFO: Loading DEX string and class tables (${dexEntries.length} dex file${dexEntries.length === 1 ? "" : "s"})`);

  const dexFiles: DexParseResult[] = [];
  for (const dexName of dexEntries) {
    const dexFile = zip.file(dexName);
    if (!dexFile) continue;
    dexFiles.push(parseDex(await dexFile.async("arraybuffer"), dexName));
  }

  const allStrings = unique(dexFiles.flatMap((dex) => dex.strings));
  const classNames = unique(dexFiles.flatMap((dex) => dex.classNames));
  emit(onProgress, 66, `SUCCESS: DEX parse complete (${classNames.length} classes, ${allStrings.length} sampled strings)`);

  emit(onProgress, 76, "INFO: Extracting META-INF certificate metadata");
  const signature = await parseSignature(zip);

  const urls = findUrls(allStrings);
  const ips = findIpAddresses(allStrings);
  emit(onProgress, 88, `INFO: Static indicators extracted (${urls.length} URLs, ${ips.length} IPs)`);
  emit(onProgress, 100, "SUCCESS: APK parser engine completed");

  return {
    fileName: file.name,
    fileSize: file.size,
    fileHash,
    manifest,
    dexFiles,
    signature,
    urls,
    ips,
    allStrings,
    classNames,
    entries,
  };
}

function emit(onProgress: ((event: ApkParseProgress) => void) | undefined, pct: number, message: string): void {
  onProgress?.({ pct, message });
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}
