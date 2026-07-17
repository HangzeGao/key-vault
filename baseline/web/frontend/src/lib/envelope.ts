// UI helpers for request payloads only. Envelope parsing and serialization are
// authoritative server-side operations exposed through inspect/convert APIs.
export function toBase64(value: string): string {
  return btoa(value);
}

export function fromBase64(value: string): string {
  try {
    return atob(value);
  } catch {
    return "";
  }
}

export function bytesToHex(value: string): string {
  try {
    return Array.from(atob(value), (char) => char.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  } catch {
    return "";
  }
}
