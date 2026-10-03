import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { Pool, type PoolConfig } from 'pg';
export function configuration() {
  try {
  const file=process.env.PHONEUNLOCK_CONFIG;
  const c=file?JSON.parse(readFileSync(file,'utf8')):{};
  c.databaseUrl=process.env.DATABASE_URL??c.databaseUrl;
  if(!c.databaseUrl)throw new Error('DATABASE_URL or PHONEUNLOCK_CONFIG is required');
  return c;
  }catch{throw new Error('Relay configuration unavailable or invalid');}
}
export function databaseCa(value: unknown): string | undefined {
  if(value===undefined || value===null || value==='')return undefined;
  const invalid=()=>new Error('DATABASE_CA_PEM must contain the complete PEM CA certificate downloaded from your database provider, not a filename or private key');
  if(typeof value!=='string')throw invalid();
  let pem=value.trim();
  if(!pem)return undefined;
  // Hosting dashboards sometimes receive a quoted PEM or literal backslash-newlines.
  if((pem.startsWith('"')&&pem.endsWith('"'))||(pem.startsWith("'")&&pem.endsWith("'")))pem=pem.slice(1,-1);
  pem=pem.replace(/\\r\\n/g,'\n').replace(/\\n/g,'\n').replace(/\r\n/g,'\n').trim();
  const blocks=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if(!blocks?.length || pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,'').trim())throw invalid();
  try {for(const block of blocks)new X509Certificate(block);}catch{throw invalid();}
  return blocks.join('\n')+'\n';
}
export function databaseOptions(c:ReturnType<typeof configuration>): PoolConfig {
  let u: URL;
  try {
    u=new URL(c.databaseUrl);
    if(!['postgres:','postgresql:'].includes(u.protocol))throw new Error();
  }catch{throw new Error('PostgreSQL configuration invalid');}
  const local=['localhost','127.0.0.1','[::1]'].includes(u.hostname);
  const ca=databaseCa(process.env.DATABASE_CA_PEM?.trim() || c.databaseCaPem);
  // pg replaces explicit TLS options if these are retained in the URL.
  for(const name of ['sslmode','sslrootcert','sslcert','sslkey'])u.searchParams.delete(name);
  return {connectionString:u.toString(),max:5,connectionTimeoutMillis:5000,
    statement_timeout:8000,idleTimeoutMillis:10000,...(!local?{ssl:{rejectUnauthorized:true,...(ca?{ca}:{})}}:{})};
}
export function database(c:ReturnType<typeof configuration>) {
  return new Pool(databaseOptions(c));
}
export function databaseFailure(error: unknown): Error {
  const code=typeof error==='object'&&error!==null&&'code' in error?String(error.code):'';
  if(['SELF_SIGNED_CERT_IN_CHAIN','DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(code)) {
    return new Error('PostgreSQL TLS certificate is not trusted. Set DATABASE_CA_PEM to the complete CA certificate from your database provider (Aiven: service Overview > CA certificate), then redeploy. Certificate verification remains required.');
  }
  if(['CERT_HAS_EXPIRED','CERT_NOT_YET_VALID','ERR_TLS_CERT_ALTNAME_INVALID'].includes(code)) {
    return new Error('PostgreSQL TLS certificate has an invalid hostname or validity period. Check the database hostname, provider certificate and CA certificate.');
  }
  // Do not include provider error messages, URLs or credentials in startup logs.
  const safeCode=/^[A-Z0-9_]{1,64}$/.test(code)?` (${code})`:'';
  return new Error(`PostgreSQL operation failed${safeCode}. Check database credentials, network access and migrations in the protected operator configuration.`);
}
