import { createHash } from 'node:crypto';
import { compactVerify, importJWK, type JWK } from 'jose';

export class ApiError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}
export function requireThat(ok: unknown, code = 'invalid_message', status = 400): asserts ok {
  if (!ok) throw new ApiError(status, code);
}
export const hash = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');
export const uuid = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
export const now = () => Math.floor(Date.now() / 1000);

// Structural scan rejects duplicate keys before JSON.parse can discard them.
export function strictJson(text: string): Record<string, any> {
  requireThat(Buffer.byteLength(text) <= 65536, 'message_too_large');
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] ?? '') && i < text.length) i++; };
  const string = (): string => {
    requireThat(text[i] === '"'); const begin = i++;
    while (i < text.length) {
      if (text[i] === '\\') { i += 2; continue; }
      if (text[i++] === '"') return JSON.parse(text.slice(begin, i));
    }
    throw new ApiError(400, 'invalid_json');
  };
  const value = (depth: number): void => {
    requireThat(depth <= 16, 'json_too_deep'); ws();
    const c = text[i];
    if (c === '"') { string(); return; }
    if (c === '{') {
      i++; ws(); const keys = new Set<string>();
      if (text[i] === '}') { i++; return; }
      for (;;) {
        ws(); const key = string(); requireThat(!keys.has(key), 'duplicate_json_key'); keys.add(key);
        ws(); requireThat(text[i++] === ':'); value(depth + 1); ws();
        if (text[i] === '}') { i++; return; } requireThat(text[i++] === ',');
      }
    }
    if (c === '[') {
      i++; ws(); if (text[i] === ']') { i++; return; }
      for (;;) { value(depth + 1); ws(); if (text[i] === ']') { i++; return; } requireThat(text[i++] === ','); }
    }
    const begin = i; while (i < text.length && !/[\s,\]}]/.test(text[i]!)) i++;
    requireThat(i > begin); JSON.parse(text.slice(begin, i));
  };
  try { value(0); ws(); requireThat(i === text.length); const parsed = JSON.parse(text);
    requireThat(parsed && typeof parsed === 'object' && !Array.isArray(parsed)); return parsed;
  } catch (e) { if (e instanceof ApiError) throw e; throw new ApiError(400, 'invalid_json'); }
}
export function publicKey(value: any): JWK {
  requireThat(value && typeof value === 'object');
  requireThat(Object.keys(value).sort().join(',') === 'crv,kty,x,y', 'invalid_public_key');
  requireThat(value.kty === 'EC' && value.crv === 'P-256', 'invalid_public_key');
  for (const part of [value.x, value.y]) requireThat(typeof part === 'string' && /^[A-Za-z0-9_-]{43}$/.test(part) && Buffer.from(part, 'base64url').length === 32, 'invalid_public_key');
  return value;
}
export function decode(token: string): Record<string, any> {
  requireThat(typeof token === 'string' && token.length <= 65536);
  const parts = token.split('.'); requireThat(parts.length === 3);
  for (const p of parts) requireThat(p && /^[A-Za-z0-9_-]+$/.test(p) && Buffer.from(p, 'base64url').toString('base64url') === p, 'invalid_base64url');
  const header = strictJson(Buffer.from(parts[0]!, 'base64url').toString('utf8'));
  requireThat(Object.keys(header).sort().join(',') === 'alg,typ' && header.alg === 'ES256' && header.typ === 'phoneunlock+jws', 'invalid_jws_header');
  requireThat(Buffer.from(parts[2]!, 'base64url').length === 64, 'invalid_signature');
  return strictJson(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
}
export async function verified(token: string, jwk: any, type: string): Promise<Record<string, any>> {
  const p = decode(token); publicKey(jwk);
  try { await compactVerify(token, await importJWK(jwk, 'ES256'), { algorithms: ['ES256'] }); }
  catch { throw new ApiError(400, 'invalid_signature'); }
  const purposeAllowed=p.purpose==='desktop-approval'||(p.purpose==='windows-unlock'&&['auth-request','auth-response'].includes(type))||(p.purpose==='password-unlock'&&['vault-delegation','vault-enroll','vault-enrolled','vault-unlock','vault-response','vault-cancel','diagnostic-batch'].includes(type));
  requireThat(p.v === 1 && purposeAllowed && p.type === type, 'invalid_purpose');
  return p;
}
export function lifetime(p: any, maximum: number): void {
  requireThat(Number.isSafeInteger(p.issuedAt) && Number.isSafeInteger(p.expiresAt), 'invalid_timestamp');
  requireThat(p.expiresAt > p.issuedAt && p.expiresAt - p.issuedAt <= maximum && p.issuedAt <= now() + 30, 'invalid_timestamp');
  requireThat(p.expiresAt > now(), 'expired', 410);
  requireThat(typeof p.nonce === 'string' && /^[A-Za-z0-9_-]{43}$/.test(p.nonce) && Buffer.from(p.nonce, 'base64url').length === 32, 'invalid_nonce');
}
export function fields(p: any, specific: string[]): void {
  const expected = ['v', 'type', 'purpose', ...specific].sort().join(',');
  requireThat(Object.keys(p).sort().join(',') === expected, 'unexpected_fields');
}
