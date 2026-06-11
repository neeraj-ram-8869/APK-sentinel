export interface DexParseResult {
  fileName: string;
  stringCount: number;
  classCount: number;
  strings: string[];
  classNames: string[];
}

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a];
const MAX_STRINGS = 250000; // Increased significantly to ensure we don't miss URLs in large APKs

export function parseDex(buffer: ArrayBuffer, fileName: string): DexParseResult {
  const data = new Uint8Array(buffer);
  const dv = new DataView(buffer);

  if (!hasDexMagic(data) || data.length < 112) {
    return { fileName, stringCount: 0, classCount: 0, strings: [], classNames: [] };
  }

  const stringIdsSize = dv.getUint32(56, true);
  const stringIdsOff = dv.getUint32(60, true);
  const typeIdsSize = dv.getUint32(64, true);
  const typeIdsOff = dv.getUint32(68, true);
  const classDefsSize = dv.getUint32(96, true);
  const classDefsOff = dv.getUint32(100, true);

  const strings = readStringTable(data, dv, stringIdsSize, stringIdsOff);
  const classNames = readClassNames(dv, strings, typeIdsSize, typeIdsOff, classDefsSize, classDefsOff);

  return {
    fileName,
    stringCount: stringIdsSize,
    classCount: classDefsSize,
    strings,
    classNames,
  };
}

export function findUrls(strings: string[]): string[] {
  const urlPattern = /\bhttps?:\/\/[^\s"'<>\\)]+/gi;
  return unique(strings.flatMap((value) => value.match(urlPattern) ?? [])).slice(0, 100);
}

export function findIpAddresses(strings: string[]): string[] {
  const ipPattern = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  return unique(strings.flatMap((value) => value.match(ipPattern) ?? [])).slice(0, 100);
}

function readStringTable(data: Uint8Array, dv: DataView, count: number, offset: number): string[] {
  const strings: string[] = [];
  const limit = Math.min(count, MAX_STRINGS);

  for (let i = 0; i < limit; i++) {
    const stringIdOffset = offset + i * 4;
    if (stringIdOffset + 4 > data.length) break;

    const stringDataOffset = dv.getUint32(stringIdOffset, true);
    if (stringDataOffset >= data.length) continue;

    const { nextOffset } = readUleb128(data, stringDataOffset);
    const end = findNullTerminator(data, nextOffset);
    if (end <= nextOffset) continue;

    const value = new TextDecoder("utf-8", { fatal: false }).decode(data.subarray(nextOffset, end));
    if (value) strings.push(value);
  }

  return strings;
}

function readClassNames(
  dv: DataView,
  strings: string[],
  typeCount: number,
  typeOffset: number,
  classCount: number,
  classOffset: number
): string[] {
  const classNames: string[] = [];

  for (let i = 0; i < classCount; i++) {
    const classDefOffset = classOffset + i * 32;
    if (classDefOffset + 4 > dv.byteLength) break;

    const classIdx = dv.getUint32(classDefOffset, true);
    if (classIdx >= typeCount) continue;

    const typeIdOffset = typeOffset + classIdx * 4;
    if (typeIdOffset + 4 > dv.byteLength) continue;

    const descriptorIdx = dv.getUint32(typeIdOffset, true);
    const descriptor = strings[descriptorIdx];
    if (!descriptor) continue;

    classNames.push(descriptorToClassName(descriptor));
  }

  return unique(classNames).slice(0, 1000);
}

function readUleb128(data: Uint8Array, offset: number): { value: number; nextOffset: number } {
  let result = 0;
  let shift = 0;
  let current = offset;

  for (let i = 0; i < 5 && current < data.length; i++) {
    const byte = data[current++];
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7;
  }

  return { value: result, nextOffset: current };
}

function findNullTerminator(data: Uint8Array, offset: number): number {
  let current = offset;
  while (current < data.length && data[current] !== 0) current++;
  return current;
}

function descriptorToClassName(descriptor: string): string {
  if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
    return descriptor.slice(1, -1).replace(/\//g, ".");
  }
  return descriptor.replace(/\//g, ".");
}

function hasDexMagic(data: Uint8Array): boolean {
  return DEX_MAGIC.every((byte, index) => data[index] === byte);
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}
