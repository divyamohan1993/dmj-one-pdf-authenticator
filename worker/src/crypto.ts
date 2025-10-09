import { b64urlEncode, b64urlDecode, ctEqual } from './utils'

// WebCrypto helpers
const te = new TextEncoder()

export async function sha256Bytes(input: Uint8Array | string): Promise<Uint8Array> {
  const data = (typeof input === 'string') ? te.encode(input) : input
  const d = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(d)
}

export async function hmacSha256B64url(keyB64: string, msg: string): Promise<string> {
  const raw = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0))
  const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', k, te.encode(msg))
  return b64urlEncode(new Uint8Array(sig))
}

/** PBKDF2 verifier for strings like: pbkdf2-sha256$200000$base64salt$base64dk */
export async function verifyPBKDF2(hashString: string, password: string): Promise<boolean> {
  const parts = hashString.split('$')
  if (parts.length !== 4 || !parts[0].startsWith('pbkdf2-')) return false
  const iterations = parseInt(parts[1], 10)
  const salt = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0))
  const dkB64 = parts[3]
  const keyMat = await crypto.subtle.importKey('raw', te.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, keyMat, 256)
  const dk = new Uint8Array(bits)
  return ctEqual(dk, Uint8Array.from(atob(dkB64), c => c.charCodeAt(0)))
}

// Base32 (RFC 4648) decode for TOTP secrets
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export function base32Decode(s: string): Uint8Array {
  s = s.toUpperCase().replace(/=+$/,'').replace(/\s+/g,'')
  let bits = 0, value = 0, out: number[] = []
  for (const ch of s) {
    const idx = B32.indexOf(ch)
    if (idx === -1) throw new Error('bad base32')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 0xff) }
  }
  return new Uint8Array(out)
}

// HOTP/TOTP
async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name:'HMAC', hash:'SHA-1' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', k, msg)
  return new Uint8Array(sig)
}
export async function hotp(secret: Uint8Array, counter: number, digits = 6): Promise<string> {
  const buf = new ArrayBuffer(8); const dv = new DataView(buf)
  dv.setUint32(4, counter >>> 0); dv.setUint32(0, Math.floor(counter / 2**32))
  const h = await hmacSha1(secret, new Uint8Array(buf))
  const offset = h[h.length - 1] & 0x0f
  const bin = ((h[offset] & 0x7f) << 24) | (h[offset+1] << 16) | (h[offset+2] << 8) | (h[offset+3])
  const code = (bin % 10**digits).toString().padStart(digits, '0')
import { b64urlEncode, b64urlDecode, ctEqual } from './utils'

// WebCrypto helpers
const te = new TextEncoder()

export async function sha256Bytes(input: Uint8Array | string): Promise<Uint8Array> {
  const data = (typeof input === 'string') ? te.encode(input) : input
  const d = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(d)
}

export async function hmacSha256B64url(keyB64: string, msg: string): Promise<string> {
  const raw = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0))
  const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', k, te.encode(msg))
  return b64urlEncode(new Uint8Array(sig))
}

/** PBKDF2 verifier for strings like: pbkdf2-sha256$200000$base64salt$base64dk */
export async function verifyPBKDF2(hashString: string, password: string): Promise<boolean> {
  const parts = hashString.split('$')
  if (parts.length !== 4 || !parts[0].startsWith('pbkdf2-')) return false
  const iterations = parseInt(parts[1], 10)
  const salt = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0))
  const dkB64 = parts[3]
  const keyMat = await crypto.subtle.importKey('raw', te.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, keyMat, 256)
  const dk = new Uint8Array(bits)
  return ctEqual(dk, Uint8Array.from(atob(dkB64), c => c.charCodeAt(0)))
}

// Base32 (RFC 4648) decode for TOTP secrets
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export function base32Decode(s: string): Uint8Array {
  s = s.toUpperCase().replace(/=+$/,'').replace(/\s+/g,'')
  let bits = 0, value = 0, out: number[] = []
  for (const ch of s) {
    const idx = B32.indexOf(ch)
    if (idx === -1) throw new Error('bad base32')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 0xff) }
  }
  return new Uint8Array(out)
}

// HOTP/TOTP
async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key, { name:'HMAC', hash:'SHA-1' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', k, msg)
  return new Uint8Array(sig)
}
export async function hotp(secret: Uint8Array, counter: number, digits = 6): Promise<string> {
  const buf = new ArrayBuffer(8); const dv = new DataView(buf)
  dv.setUint32(4, counter >>> 0); dv.setUint32(0, Math.floor(counter / 2**32))
  const h = await hmacSha1(secret, new Uint8Array(buf))
  const offset = h[h.length - 1] & 0x0f
  const bin = ((h[offset] & 0x7f) << 24) | (h[offset+1] << 16) | (h[offset+2] << 8) | (h[offset+3])
  const code = (bin % 10**digits).toString().padStart(digits, '0')
  return code
}
export async function verifyTotp(secret: Uint8Array, code: string, window = 1, step = 30): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000)
  const counter = Math.floor(now / step)
  for (let i = -window; i <= window; i++) {
    const c = await hotp(secret, counter + i, 6)
    if (c === code) return true
  }
  return false
}

// AES-GCM for sealing TOTP secret at rest (env master key base64)
export async function sealAesGcm(masterKeyB64: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const keyRaw = Uint8Array.from(atob(masterKeyB64), c => c.charCodeAt(0))
  const key = await crypto.subtle.importKey('raw', keyRaw, { name:'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  const out = new Uint8Array(iv.length + (ct as ArrayBuffer).byteLength)
  out.set(iv, 0); out.set(new Uint8Array(ct), iv.length)
  return out
}
export async function openAesGcm(masterKeyB64: string, sealed: Uint8Array): Promise<Uint8Array> {
  const keyRaw = Uint8Array.from(atob(masterKeyB64), c => c.charCodeAt(0))
  const key = await crypto.subtle.importKey('raw', keyRaw, { name:'AES-GCM' }, false, ['decrypt'])
  const iv = sealed.slice(0, 12); const ct = sealed.slice(12)
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct)
  return new Uint8Array(pt)
}
  return code
}
export async function verifyTotp(secret: Uint8Array, code: string, window = 1, step = 30): Promise<boolean> {
  const now = Math.floor(Date.now() / 1000)
  const counter = Math.floor(now / step)
  for (let i = -window; i <= window; i++) {
    const c = await hotp(secret, counter + i, 6)
    if (c === code) return true
  }
  return false
}

// AES-GCM for sealing TOTP secret at rest (env master key base64)
export async function sealAesGcm(masterKeyB64: string, plaintext: Uint8Array): Promise<Uint8Array> {
  const keyRaw = Uint8Array.from(atob(masterKeyB64), c => c.charCodeAt(0))
  const key = await crypto.subtle.importKey('raw', keyRaw, { name:'AES-GCM' }, false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)
  const out = new Uint8Array(iv.length + (ct as ArrayBuffer).byteLength)
  out.set(iv, 0); out.set(new Uint8Array(ct), iv.length)
  return out
}
export async function openAesGcm(masterKeyB64: string, sealed: Uint8Array): Promise<Uint8Array> {
  const keyRaw = Uint8Array.from(atob(masterKeyB64), c => c.charCodeAt(0))
  const key = await crypto.subtle.importKey('raw', keyRaw, { name:'AES-GCM' }, false, ['decrypt'])
  const iv = sealed.slice(0, 12); const ct = sealed.slice(12)
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct)
  return new Uint8Array(pt)
}
