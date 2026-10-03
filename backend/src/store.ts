import { Pool, type PoolClient } from 'pg';
export type Table = 'users' | 'windows_devices' | 'android_devices' | 'device_pairings' | 'pairing_sessions' | 'authentication_requests' | 'authentication_events' | 'remote_offers' | 'remote_commands' | 'camera_frames' | 'rate_limits';
export type Row = Record<string, any>;
export interface Store {
  get(table: Table, id: string): Promise<Row | undefined>;
  all(table: Table): Promise<Row[]>;
  find(table: Table, field: string, value: string): Promise<Row[]>;
  rateLimit(key: string, maximum: number): Promise<boolean>;
  put(table: Table, id: string, value: Row): Promise<void>;
  insert(table: Table, id: string, value: Row): Promise<void>;
  transaction<T>(fn: (store: Store) => Promise<T>): Promise<T>;
}
export class PgStore implements Store {
  constructor(private db: Pool | PoolClient) {}
  async get(table: Table, id: string) { const r = await this.db.query(`SELECT data FROM ${table} WHERE id=$1 FOR UPDATE`, [id]); return r.rows[0]?.data as Row | undefined; }
  async all(table: Table) { return (await this.db.query(`SELECT data FROM ${table}`)).rows.map(r => r.data as Row); }
  async find(table: Table, field: string, value: string) { return (await this.db.query(`SELECT data FROM ${table} WHERE data->>$1=$2`,[field,value])).rows.map(r=>r.data as Row); }
  async rateLimit(key: string, maximum: number) {
    const bucket=Math.floor(Date.now()/60000);
    const r=await this.db.query(`INSERT INTO rate_limits(id,data) VALUES($1,jsonb_build_object('bucket',$2::bigint,'count',1))
      ON CONFLICT(id) DO UPDATE SET data=CASE WHEN (rate_limits.data->>'bucket')::bigint=$2
      THEN jsonb_build_object('bucket',$2::bigint,'count',(rate_limits.data->>'count')::int+1)
      ELSE jsonb_build_object('bucket',$2::bigint,'count',1) END RETURNING data`,[key,bucket]);
    return r.rows[0].data.count<=maximum;
  }
  async put(table: Table, id: string, value: Row) { await this.db.query(`INSERT INTO ${table}(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data`, [id, value]); }
  async insert(table: Table, id: string, value: Row) { await this.db.query(`INSERT INTO ${table}(id,data) VALUES($1,$2)`, [id, value]); }
  async transaction<T>(fn: (store: Store) => Promise<T>): Promise<T> {
    if (!(this.db instanceof Pool)) return fn(this);
    const client = await this.db.connect();
    try { await client.query('BEGIN'); const result = await fn(new PgStore(client)); await client.query('COMMIT'); return result; }
    catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }
}
// Only dependency-injected tests use memory; the runnable server requires PostgreSQL.
export class MemoryStore implements Store {
  private rows = new Map<string, Row>(); private tail: Promise<void> = Promise.resolve();
  async get(t: Table, id: string) { const r = this.rows.get(`${t}/${id}`); return r ? structuredClone(r) : undefined; }
  async all(t: Table) { return [...this.rows].filter(([k]) => k.startsWith(`${t}/`)).map(([,r]) => structuredClone(r)); }
  async find(t:Table,field:string,value:string) {return (await this.all(t)).filter(r=>String(r[field])===value);}
  async rateLimit(key:string,maximum:number) {const bucket=Math.floor(Date.now()/60000);const r=await this.get('rate_limits',key);const count=r?.bucket===bucket?r.count+1:1;await this.put('rate_limits',key,{bucket,count});return count<=maximum;}
  async put(t: Table, id: string, r: Row) { this.rows.set(`${t}/${id}`, structuredClone(r)); }
  async insert(t: Table, id: string, r: Row) { if (this.rows.has(`${t}/${id}`)) throw Object.assign(new Error('duplicate'), {code:'23505'}); await this.put(t,id,r); }
  async transaction<T>(fn: (s: Store) => Promise<T>): Promise<T> { const before = this.tail; let release!: () => void;
    this.tail = new Promise<void>(resolve => { release = resolve; }); await before; const backup = structuredClone(this.rows);
    try { return await fn(this); } catch(e) { this.rows = backup; throw e; } finally { release(); }
  }
}
