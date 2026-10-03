import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import { hash, publicKey, uuid } from './protocol.js';
import {configuration,database} from './config.js';
const [command,...args]=process.argv.slice(2);
const pool=database(configuration());
try {
  if(command==='migrate') {
    for(const name of ['001_initial.sql','002_remote.sql'])await pool.query(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));
  }
  else if(command==='prune') {
    const cutoff=Math.floor(Date.now()/1000);
    await pool.query('DELETE FROM camera_frames WHERE (data->>\'expiresAt\')::bigint<$1',[cutoff]);
    await pool.query('DELETE FROM rate_limits WHERE (data->>\'bucket\')::bigint<$1',[Math.floor(Date.now()/60000)-2]);
    for(const table of ['remote_commands','remote_offers','pairing_sessions'])await pool.query(`DELETE FROM ${table} WHERE (data->>'expiresAt')::bigint<$1`,[cutoff-86400]);
    console.log('Expired transport data removed');
  }
  else if(command==='bootstrap') {
    if(args.length!==2)throw new Error('bootstrap <windows-public.json> <bootstrap-output.json>');
    const w=JSON.parse(readFileSync(args[0]!,'utf8'));if(!uuid(w.id))throw new Error('Invalid device ID');publicKey(w.jwk);
    const token=randomBytes(32).toString('base64url');const userId=randomUUID();
    const db=await pool.connect();try {await db.query('BEGIN');
      await db.query('INSERT INTO users(id,data) VALUES($1,$2)',[userId,{id:userId,label:'Local development'}]);
      await db.query('INSERT INTO windows_devices(id,data) VALUES($1,$2)',[w.id,{...w,userId,tokenHash:hash(token)}]);
      await db.query('COMMIT');
    } catch(e){await db.query('ROLLBACK');throw e;}finally{db.release();}
    writeFileSync(args[1]!,JSON.stringify({transportToken:token},null,2),{mode:0o600});
    console.log('Bootstrap file written; import into the Windows client and delete it.');
  } else throw new Error('Expected migrate or bootstrap');
}finally{await pool.end();}
