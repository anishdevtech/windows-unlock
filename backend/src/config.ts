import { readFileSync } from 'node:fs';
import { Pool } from 'pg';
export function configuration() {
  try {
  const file=process.env.PHONEUNLOCK_CONFIG;
  const c=file?JSON.parse(readFileSync(file,'utf8')):{};
  c.databaseUrl=process.env.DATABASE_URL??c.databaseUrl;
  if(!c.databaseUrl)throw new Error('DATABASE_URL or PHONEUNLOCK_CONFIG is required');
  return c;
  }catch{throw new Error('Relay configuration unavailable or invalid');}
}
export function database(c:ReturnType<typeof configuration>) {
  try {
  const u=new URL(c.databaseUrl);const local=['localhost','127.0.0.1','::1'].includes(u.hostname);
  const ca=process.env.DATABASE_CA_PEM??c.databaseCaPem;
  for(const name of ['sslmode','sslrootcert','sslcert','sslkey'])u.searchParams.delete(name);
  return new Pool({connectionString:u.toString(),max:5,connectionTimeoutMillis:5000,
    statement_timeout:8000,idleTimeoutMillis:10000,...(!local?{ssl:{rejectUnauthorized:true,...(ca?{ca}:{})}}:{})});
  }catch{throw new Error('PostgreSQL configuration invalid');}
}
