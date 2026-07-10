/**
 * crypto-compat.ts
 * AES-256-GCM + PBKDF2 that work in BOTH secure contexts (HTTPS/localhost)
 * AND insecure contexts (plain HTTP on a LAN IP like 192.168.x.x).
 *
 * THE PROBLEM:
 *   window.crypto.subtle is undefined when window.isSecureContext === false.
 *   This happens when the page is served over plain HTTP from any address
 *   other than localhost/127.0.0.1.  Mobile browsers opening
 *   http://192.168.x.x:8000/ are therefore completely unable to run any
 *   crypto operation — every call throws immediately with no feedback.
 *
 * THE SOLUTION:
 *   At call-time, detect whether we are in a secure context.
 *   If yes  → use native crypto.subtle (fast, hardware-accelerated).
 *   If no   → lazy-load @noble/ciphers (AES-GCM) and @noble/hashes (PBKDF2).
 *
 * NOTE: crypto.getRandomValues is available in ALL contexts and needs no fallback.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

// ─── Noble lazy cache ──────────────────────────────────────────────────────
let _nobleLoading: Promise<void> | null = null;
let _gcm: any = null;
let _pbkdf2: any = null;
let _sha256: any = null;

async function ensureNoble(): Promise<void> {
  if (_gcm !== null) return;
  if (_nobleLoading) { await _nobleLoading; return; }
  _nobleLoading = (async () => {
    const [aes, pb, sh] = await Promise.all([
      // @ts-ignore – resolved by Vite bundler at runtime
      import('@noble/ciphers/aes.js'),
      // @ts-ignore
      import('@noble/hashes/pbkdf2.js'),
      // @ts-ignore  sha256 lives in sha2.js in @noble/hashes
      import('@noble/hashes/sha2.js'),
    ]);
    _gcm    = aes.gcm;
    _pbkdf2 = pb.pbkdf2;
    _sha256 = sh.sha256;
  })();
  await _nobleLoading;
}

// ─── Secure-context check ───────────────────────────────────────────────────
const hasNativeCrypto = (): boolean =>
  typeof window !== 'undefined' &&
  window.isSecureContext === true &&
  typeof crypto !== 'undefined' &&
  crypto.subtle != null;

// ─── Helpers to guarantee plain ArrayBuffer (never SharedArrayBuffer) ───────
// TypeScript's strict lib defs require ArrayBuffer, not ArrayBufferLike.
// These helpers satisfy the type checker while remaining safe at runtime.
function asArrayBuffer(v: ArrayBufferLike): ArrayBuffer {
  if (v instanceof ArrayBuffer) return v;
  const ab = new ArrayBuffer(v.byteLength);
  new Uint8Array(ab).set(new Uint8Array(v));
  return ab;
}
// Return a Uint8Array whose .buffer is a plain ArrayBuffer.
// The 'as unknown as Uint8Array<ArrayBuffer>' cast is necessary because
// TypeScript widens Uint8Array constructed from sliced buffers to
// Uint8Array<ArrayBufferLike>, which crypto.subtle refuses.
function safeU8(src: Uint8Array | ArrayBuffer): Uint8Array<ArrayBuffer> {
  const plain = src instanceof ArrayBuffer
    ? src
    : asArrayBuffer(src.buffer).slice(src.byteOffset, src.byteOffset + src.byteLength);
  return new Uint8Array(plain) as unknown as Uint8Array<ArrayBuffer>;
}
function safeAB(src: ArrayBuffer | ArrayBufferLike): ArrayBuffer {
  return asArrayBuffer(src);
}

// ─── AesKey type ────────────────────────────────────────────────────────────
export type AesKey =
  | { kind: 'native'; key: CryptoKey }
  | { kind: 'raw';    bytes: Uint8Array };

const isNative = (k: AesKey): k is { kind: 'native'; key: CryptoKey } => k.kind === 'native';

// ─── generateAesKey ─────────────────────────────────────────────────────────
export async function generateAesKey(): Promise<AesKey> {
  if (hasNativeCrypto()) {
    const k = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'],
    );
    return { kind: 'native', key: k };
  }
  return { kind: 'raw', bytes: crypto.getRandomValues(new Uint8Array(32)) };
}

// ─── importAesKey ───────────────────────────────────────────────────────────
export async function importAesKey(
  raw: Uint8Array | ArrayBuffer,
  usages: KeyUsage[],
): Promise<AesKey> {
  const bytes = safeU8(raw instanceof ArrayBuffer ? raw : raw);
  if (hasNativeCrypto()) {
    const k = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', true, usages);
    return { kind: 'native', key: k };
  }
  return { kind: 'raw', bytes: bytes.slice() };
}

// ─── exportAesKey ───────────────────────────────────────────────────────────
export async function exportAesKey(key: AesKey): Promise<ArrayBuffer> {
  if (isNative(key)) return crypto.subtle.exportKey('raw', key.key);
  return safeAB(key.bytes.buffer);
}

// ─── aesGcmEncrypt ──────────────────────────────────────────────────────────
export async function aesGcmEncrypt(
  plain: ArrayBuffer,
  key: AesKey,
  iv: Uint8Array,
): Promise<ArrayBuffer> {
  const sp = safeAB(plain);
  const si = safeU8(iv);
  if (isNative(key)) {
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: si }, key.key, sp);
  }
  await ensureNoble();
  return safeAB((_gcm(key.bytes, si).encrypt(new Uint8Array(sp)) as Uint8Array).buffer);
}

// ─── aesGcmDecrypt ──────────────────────────────────────────────────────────
export async function aesGcmDecrypt(
  cipher: ArrayBuffer,
  key: AesKey,
  iv: Uint8Array,
): Promise<ArrayBuffer> {
  const sc = safeAB(cipher);
  const si = safeU8(iv);
  if (isNative(key)) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: si }, key.key, sc);
  }
  await ensureNoble();
  // noble/ciphers throws if auth tag is bad — same as Web Crypto API
  return safeAB((_gcm(key.bytes, si).decrypt(new Uint8Array(sc)) as Uint8Array).buffer);
}

// ─── pbkdf2Key ──────────────────────────────────────────────────────────────
export async function pbkdf2Key(
  password: string,
  salt: Uint8Array,
  iterations = 100_000,
): Promise<AesKey> {
  const pwdBytes = new TextEncoder().encode(password);
  const ss       = safeU8(salt);
  if (hasNativeCrypto()) {
    const base = await crypto.subtle.importKey('raw', pwdBytes, 'PBKDF2', false, ['deriveKey']);
    const k = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: safeAB(ss.buffer), iterations, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'],
    );
    return { kind: 'native', key: k };
  }
  await ensureNoble();
  const bytes = _pbkdf2(_sha256, pwdBytes, ss, { c: iterations, dkLen: 32 }) as Uint8Array;
  return { kind: 'raw', bytes };
}

// ─── wrapAesKey ─────────────────────────────────────────────────────────────
export async function wrapAesKey(
  fileKey: AesKey,
  wrappingKey: AesKey,
  iv: Uint8Array,
): Promise<ArrayBuffer> {
  const si = safeU8(iv);
  if (isNative(fileKey) && isNative(wrappingKey)) {
    return crypto.subtle.wrapKey('raw', fileKey.key, wrappingKey.key, { name: 'AES-GCM', iv: si });
  }
  const rawFile = new Uint8Array(await exportAesKey(fileKey));
  return aesGcmEncrypt(safeAB(rawFile.buffer), wrappingKey, si);
}

// ─── unwrapAesKey ───────────────────────────────────────────────────────────
export async function unwrapAesKey(
  wrappedKey: ArrayBuffer,
  wrappingKey: AesKey,
  iv: Uint8Array,
): Promise<AesKey> {
  const sw = safeAB(wrappedKey);
  const si = safeU8(iv);
  if (isNative(wrappingKey)) {
    try {
      const k = await crypto.subtle.unwrapKey(
        'raw', sw, wrappingKey.key,
        { name: 'AES-GCM', iv: si },
        'AES-GCM', true, ['decrypt'],
      );
      return { kind: 'native', key: k };
    } catch { throw new Error('Wrong password'); }
  }
  try {
    const raw = new Uint8Array(await aesGcmDecrypt(sw, wrappingKey, si));
    return { kind: 'raw', bytes: raw };
  } catch { throw new Error('Wrong password'); }
}
