import JSZip from "jszip";

export interface ApkSignatureInfo {
  files: string[];
  certificateFiles: string[];
  manifestFile?: string;
  signerSummary: string;
  fingerprintSha256?: string;
  debugKey: boolean;
  selfSigned: boolean;
  status: "TRUSTED" | "WARNING" | "UNTRUSTED";
}

const CERT_EXTENSIONS = /\.(RSA|DSA|EC)$/i;

export async function parseSignature(zip: JSZip): Promise<ApkSignatureInfo> {
  const metaFiles = Object.keys(zip.files)
    .filter((name) => /^META-INF\//i.test(name) && !zip.files[name].dir)
    .sort();
  const certificateFiles = metaFiles.filter((name) => CERT_EXTENSIONS.test(name));
  const manifestFile = metaFiles.find((name) => /MANIFEST\.MF$/i.test(name));

  let fingerprintSha256: string | undefined;
  let debugKey = false;
  let signerSummary = certificateFiles.length > 0
    ? `Certificate container: ${certificateFiles.join(", ")}`
    : "No META-INF certificate container found";

  const firstCert = certificateFiles[0] ? zip.file(certificateFiles[0]) : null;
  if (firstCert) {
    const bytes = await firstCert.async("uint8array");
    fingerprintSha256 = await sha256Hex(bytes);
    const ascii = lossyAscii(bytes);
    debugKey = /Android Debug|CN=Android Debug|debug/i.test(ascii);
    const cn = ascii.match(/CN=([A-Za-z0-9 ._-]{3,80})/)?.[1];
    if (cn) signerSummary = `CN=${cn}`;
  }

  return {
    files: metaFiles,
    certificateFiles,
    manifestFile,
    signerSummary,
    fingerprintSha256,
    debugKey,
    selfSigned: certificateFiles.length > 0,
    status: certificateFiles.length === 0 || debugKey ? "UNTRUSTED" : "WARNING",
  };
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) return "";
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join(":")
    .toUpperCase();
}

function lossyAscii(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : " "))
    .join("");
}
