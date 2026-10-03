import { readFileSync } from 'node:fs';
import Fastify from 'fastify';
import { configureApp,serverOptions } from './relay.js';
import { PgStore } from './store.js';
import { configuration,database,databaseFailure } from './config.js';
import { firebasePush } from './push.js';
import { listenForRuntime } from './runtime.js';

const c=configuration();
const managed=process.env.VERCEL==='1';
if (!managed&&(!c.tlsKey || !c.tlsCert)) throw new Error('TLS configuration is required outside Vercel');
const pool=database(c);
try {await pool.query('SELECT 1');}
catch(error) {await pool.end();throw databaseFailure(error);}
// Vercel's Fastify detector requires the entry point itself to import Fastify.
const app=Fastify(serverOptions(managed?undefined:{key:readFileSync(c.tlsKey),cert:readFileSync(c.tlsCert)}));
configureApp(app,new PgStore(pool),firebasePush());
await listenForRuntime(app,{host:managed?'0.0.0.0':c.host??'127.0.0.1',port:Number(process.env.PORT??c.port??(managed?3000:8443))},managed);
console.log('WINDOWS-UNLOCK relay ready; Windows sign-in remains unchanged');
let closing=false;
for(const signal of ['SIGINT','SIGTERM'] as const) process.on(signal,()=>{
  if(closing)return;closing=true;void app.close().then(()=>pool.end());
});
