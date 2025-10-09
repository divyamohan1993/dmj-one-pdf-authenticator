export function bytesToHex(u8: Uint8Array): string {
  return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('')
}
export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) throw new Error('bad hex')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i*2, i*2+2), 16)
  return out
}
export function b64urlEncode(u8: Uint8Array): string {
  const s = btoa(String.fromCharCode(...u8))
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'')
}
export function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, '+').replace(/_/g, '/'); s += '==='.slice((s.length + 3) % 4)
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}
// constant-time-ish compare
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let res = 0
  for (let i = 0; i < a.length; i++) res |= a[i] ^ b[i]
  return res === 0
}
