// ===================================================================
// Android Binary XML (AXML) → ManifestInfo decoder
//
// APK manifests are stored as binary XML (ResXMLTree) defined in
// AOSP: frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
//
// Chunk layout for each node:
//   [0] ResChunk_header:  type(u16) + headerSize(u16) + size(u32)  = 8 bytes
//   [8] ResXMLTree_node:  lineNumber(u32) + comment(i32)           = 8 bytes
//  [16] chunk-specific extension follows
// ===================================================================

const AXML_MAGIC           = 0x0003;
const CHUNK_STRING_POOL    = 0x0001;
const CHUNK_XML_RES_MAP    = 0x0180;
const CHUNK_NS_START       = 0x0100;
const CHUNK_NS_END         = 0x0101;
const CHUNK_ELEM_START     = 0x0102;
const CHUNK_ELEM_END       = 0x0103;
const CHUNK_CDATA          = 0x0104;
const UTF8_FLAG            = 0x00000100;

// Res_value dataType constants
const TYPE_STRING  = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
const TYPE_INT_BOOL = 0x12;
const TYPE_REF     = 0x01;

// ===========================
// Public types
// ===========================

export interface ComponentInfo {
  name: string;
  exported: boolean;
  actions: string[];
}

export interface ManifestInfo {
  packageName: string;
  versionCode: number;
  versionName: string;
  minSdkVersion: number;
  targetSdkVersion: number;
  permissions: string[];
  activities: ComponentInfo[];
  services: ComponentInfo[];
  receivers: ComponentInfo[];
  providers: ComponentInfo[];
  isDebuggable: boolean;
  allowBackup: boolean;
  xmlString: string;
  error?: string;
}

// ===========================
// String pool parsing
// ===========================

/**
 * Parse the ResStringPool_header and return the full decoded string array.
 *
 * ResStringPool_header layout (28 bytes):
 *   [0]  ResChunk_header   (8 bytes: type, headerSize, size)
 *   [8]  stringCount  u32
 *   [12] styleCount   u32
 *   [16] flags        u32  (bit 8 = UTF-8)
 *   [20] stringsStart u32  (offset from chunk start to first string data)
 *   [24] stylesStart  u32
 *
 * Immediately after the 28-byte header: stringCount × u32 offset table.
 * Each offset is relative to stringsStart (= chunk start + stringsStart).
 */
function parseStringPool(data: Uint8Array, chunkOffset: number): string[] {
  const dv = new DataView(data.buffer, data.byteOffset + chunkOffset);

  const headerSize  = dv.getUint16(2, true);
  const stringCount = dv.getUint32(8, true);
  const flags       = dv.getUint32(16, true);
  const stringsStart = dv.getUint32(20, true);
  const isUtf8 = (flags & UTF8_FLAG) !== 0;

  // Offset table immediately follows the pool header
  const offsetTableBase = headerSize; // from chunkOffset
  // Absolute index into `data` for the start of string data
  const strDataBase = chunkOffset + stringsStart;

  const result: string[] = [];
  for (let i = 0; i < stringCount; i++) {
    const relOffset = dv.getUint32(offsetTableBase + i * 4, true);
    const absOffset = strDataBase + relOffset;
    result.push(decodePoolString(data, absOffset, isUtf8));
  }
  return result;
}

/**
 * Decode a single string from the string-data section.
 *
 * UTF-8 encoding:
 *   byte[0-1]:  char count (1 byte, or 2 bytes if high bit set)
 *   byte[...]:  byte count (1 byte, or 2 bytes if high bit set)
 *   byte[...]:  UTF-8 bytes (byteCount of them)
 *   byte:       NUL terminator
 *
 * UTF-16 encoding:
 *   uint16:     char count
 *   uint16 × n: UTF-16LE chars
 *   uint16:     NUL terminator (0x0000)
 */
function decodePoolString(data: Uint8Array, absOffset: number, utf8: boolean): string {
  if (absOffset >= data.length) return '';
  try {
    if (utf8) {
      let off = absOffset;
      // Skip char-length prefix (1 or 2 bytes)
      off += (data[off] & 0x80) ? 2 : 1;
      // Read byte-length prefix
      let byteLen: number;
      if (data[off] & 0x80) {
        byteLen = ((data[off] & 0x7F) << 8) | data[off + 1];
        off += 2;
      } else {
        byteLen = data[off++];
      }
      if (off + byteLen > data.length) return '';
      return new TextDecoder('utf-8').decode(data.subarray(off, off + byteLen));
    } else {
      const dv = new DataView(data.buffer, data.byteOffset + absOffset);
      const charLen = dv.getUint16(0, true);
      let str = '';
      for (let i = 0; i < charLen; i++) {
        str += String.fromCharCode(dv.getUint16(2 + i * 2, true));
      }
      return str;
    }
  } catch {
    return '';
  }
}

// ===========================
// Attribute value decoding
// ===========================

/**
 * Each ResXMLTree_attribute is 20 bytes:
 *   [0]  ns        i32  — string-pool index of namespace URI (-1 = none)
 *   [4]  name      i32  — string-pool index of attribute name
 *   [8]  rawValue  i32  — string-pool index of raw string value (-1 if typed)
 *   [12] size      u16  = 8  (Res_value.size)
 *   [14] res0      u8   = 0
 *   [15] dataType  u8
 *   [16] data      i32
 */
function readAttrValue(
  dv: DataView,   // DataView over the *whole* file buffer
  attrOffset: number, // absolute byte offset of this attribute
  pool: string[]
): string {
  const dataType = dv.getUint8(attrOffset + 15);
  const data     = dv.getInt32(attrOffset + 16, true);

  switch (dataType) {
    case TYPE_STRING: {
      const s = pool[data];
      return s ?? '';
    }
    case TYPE_INT_DEC: return data.toString();
    case TYPE_INT_HEX: return `0x${(data >>> 0).toString(16)}`;
    case TYPE_INT_BOOL: return data !== 0 ? 'true' : 'false';
    case TYPE_REF:     return `@0x${(data >>> 0).toString(16)}`;
    default: {
      // Try raw-value string first
      const raw = dv.getInt32(attrOffset + 8, true);
      if (raw >= 0 && raw < pool.length) return pool[raw] ?? data.toString();
      return data.toString();
    }
  }
}

// ===========================
// Main decoder
// ===========================

export function decodeManifest(buffer: ArrayBuffer): ManifestInfo {
  const data = new Uint8Array(buffer);
  const dv   = new DataView(buffer);

  const info: ManifestInfo = {
    packageName: '',
    versionCode: 0,
    versionName: '',
    minSdkVersion: 0,
    targetSdkVersion: 0,
    permissions: [],
    activities: [],
    services: [],
    receivers: [],
    providers: [],
    isDebuggable: false,
    allowBackup: true,
    xmlString: '',
  };

  // Validate AXML magic (first 2 bytes of the ResXMLTree_header)
  if (data.length < 8 || dv.getUint16(0, true) !== AXML_MAGIC) {
    // Fallback: try plain-text XML (some test APKs keep it uncompressed)
    const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
    if (text.trimStart().startsWith('<?xml') || text.includes('<manifest')) {
      info.xmlString = text;
      parsePlainTextManifest(text, info);
      return info;
    }
    info.error = `Not a valid AXML file (magic=0x${dv.getUint16(0, true).toString(16)})`;
    return info;
  }

  const fileSize = Math.min(dv.getUint32(4, true), buffer.byteLength);
  let offset = 8; // skip ResXMLTree_header (8 bytes)

  let pool: string[] = [];
  const nsUriToPrefix = new Map<string, string>(); // uri → prefix
  const xmlLines: string[] = ['<?xml version="1.0" encoding="utf-8"?>'];
  const elemStack: string[] = [];
  let depth = 0;

  while (offset + 8 <= fileSize) {
    const type    = dv.getUint16(offset, true);
    const size    = dv.getUint32(offset + 4, true);

    if (size === 0 || offset + size > fileSize) break;

    switch (type) {
      // ── String Pool ────────────────────────────────────────────────
      case CHUNK_STRING_POOL: {
        pool = parseStringPool(data, offset);
        break;
      }

      // ── Resource Map: skip ────────────────────────────────────────
      case CHUNK_XML_RES_MAP:
        break;

      // ── Namespace Start ───────────────────────────────────────────
      case CHUNK_NS_START: {
        // [16] prefix idx  [20] uri idx
        const pfxIdx = dv.getInt32(offset + 16, true);
        const uriIdx = dv.getInt32(offset + 20, true);
        const pfx = (pfxIdx >= 0 && pfxIdx < pool.length) ? pool[pfxIdx] : null;
        const uri = (uriIdx >= 0 && uriIdx < pool.length) ? pool[uriIdx] : null;
        if (pfx && uri) nsUriToPrefix.set(uri, pfx);
        break;
      }

      // ── Namespace End: skip ───────────────────────────────────────
      case CHUNK_NS_END:
        break;

      // ── Start Element ─────────────────────────────────────────────
      case CHUNK_ELEM_START: {
        //  [16] ResXMLTree_attrExt starts here:
        //       ns(i32) name(i32) attributeStart(u16) attributeSize(u16)
        //       attributeCount(u16) idIdx(u16) classIdx(u16) styleIdx(u16)
        const nameIdx      = dv.getInt32(offset + 20, true);
        const attrStart    = dv.getUint16(offset + 24, true); // from ResXMLTree_attrExt start (=offset+16)
        const attrSize     = dv.getUint16(offset + 26, true); // usually 20
        const attrCount    = dv.getUint16(offset + 28, true);

        const elemName = safeStr(pool, nameIdx);
        elemStack.push(elemName);
        depth++;

        // Attributes start at: offset+16 (ResXMLTree_attrExt base) + attrStart
        const attrsBase = offset + 16 + attrStart;
        // Collect into two maps: raw name → value, and qualified prefix:name → value
        const attrsRaw: Record<string, string> = {};

        for (let a = 0; a < attrCount; a++) {
          const ao = attrsBase + a * attrSize;
          if (ao + attrSize > buffer.byteLength) break;
          const attrNameIdx = dv.getInt32(ao + 4, true);
          const attrName    = safeStr(pool, attrNameIdx);
          if (!attrName) continue;
          attrsRaw[attrName] = readAttrValue(dv, ao, pool);
        }

        // Extract semantic data
        extractElementData(elemName, attrsRaw, info);

        // Build human-readable XML line
        const ind = '  '.repeat(depth - 1);
        const attrXml: string[] = [];
        // Add xmlns declarations once at root depth
        if (depth === 1) {
          for (const [uri, pfx] of nsUriToPrefix) {
            attrXml.push(`xmlns:${pfx}="${xmlEsc(uri)}"`);
          }
        }
        for (const [k, v] of Object.entries(attrsRaw)) {
          attrXml.push(`android:${k}="${xmlEsc(v)}"`);
        }
        const attrStr = attrXml.length ? ' ' + attrXml.join(' ') : '';
        xmlLines.push(`${ind}<${elemName}${attrStr}>`);
        break;
      }

      // ── End Element ───────────────────────────────────────────────
      case CHUNK_ELEM_END: {
        const name = elemStack.pop() ?? 'unknown';
        depth = Math.max(0, depth - 1);
        xmlLines.push(`${'  '.repeat(depth)}</${name}>`);
        break;
      }

      // ── CDATA ─────────────────────────────────────────────────────
      case CHUNK_CDATA: {
        const dataIdx = dv.getInt32(offset + 16, true);
        const text = safeStr(pool, dataIdx);
        if (text) xmlLines.push(`${'  '.repeat(depth)}${xmlEsc(text)}`);
        break;
      }
    }

    offset += size;
  }

  info.xmlString = xmlLines.join('\n');
  return info;
}

// ===========================
// Element semantic extractor
// ===========================

function extractElementData(
  elem: string,
  attrs: Record<string, string>,
  info: ManifestInfo
): void {
  switch (elem) {
    case 'manifest':
      info.packageName  = attrs['package'] ?? '';
      info.versionCode  = parseInt(attrs['versionCode'] ?? '0', 10) || 0;
      info.versionName  = attrs['versionName'] ?? '';
      break;

    case 'uses-sdk':
      info.minSdkVersion    = parseInt(attrs['minSdkVersion'] ?? '0', 10) || 0;
      info.targetSdkVersion = parseInt(attrs['targetSdkVersion'] ?? '0', 10) || 0;
      break;

    case 'uses-permission':
    case 'uses-permission-sdk-23': {
      const p = attrs['name'];
      if (p && !info.permissions.includes(p)) info.permissions.push(p);
      break;
    }

    case 'application':
      info.isDebuggable = (attrs['debuggable'] ?? 'false') === 'true';
      info.allowBackup  = (attrs['allowBackup'] ?? 'true') !== 'false';
      break;

    case 'activity':
      info.activities.push(makeComponent(attrs, info.packageName));
      break;

    case 'service':
      info.services.push(makeComponent(attrs, info.packageName));
      break;

    case 'receiver':
      info.receivers.push(makeComponent(attrs, info.packageName));
      break;

    case 'provider':
      info.providers.push(makeComponent(attrs, info.packageName));
      break;
  }
}

function makeComponent(attrs: Record<string, string>, pkg: string): ComponentInfo {
  return {
    name: resolveClass(attrs['name'] ?? '', pkg),
    exported: attrs['exported'] === 'true',
    actions: [],
  };
}

// ===========================
// Plain-text XML fallback
// ===========================

function parsePlainTextManifest(xml: string, info: ManifestInfo): void {
  const get = (tag: string, attr: string): string => {
    const re = new RegExp(`<${tag}[^>]*${attr}\\s*=\\s*["']([^"']+)["']`, 'i');
    return xml.match(re)?.[1] ?? '';
  };
  info.packageName      = get('manifest', 'package');
  info.versionName      = get('manifest', 'android:versionName');
  info.versionCode      = parseInt(get('manifest', 'android:versionCode'), 10) || 0;
  info.minSdkVersion    = parseInt(get('uses-sdk', 'android:minSdkVersion'), 10) || 0;
  info.targetSdkVersion = parseInt(get('uses-sdk', 'android:targetSdkVersion'), 10) || 0;
  info.isDebuggable     = get('application', 'android:debuggable') === 'true';

  for (const m of xml.matchAll(/uses-permission[^>]*android:name\s*=\s*["']([^"']+)["']/gi)) {
    if (!info.permissions.includes(m[1])) info.permissions.push(m[1]);
  }
}

// ===========================
// Helpers
// ===========================

function safeStr(pool: string[], idx: number): string {
  if (idx < 0 || idx >= pool.length) return '';
  return pool[idx] ?? '';
}

function resolveClass(name: string, pkg: string): string {
  if (!name || !pkg) return name;
  if (name.startsWith('.')) return pkg + name;
  if (!name.includes('.')) return `${pkg}.${name}`;
  return name;
}

function xmlEsc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
