import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash,X509Certificate} from 'node:crypto';
import pg from '../backend/node_modules/pg/lib/index.js';
const root=process.argv[2];if(!root)throw new Error('Project root required');const runtime=join(root,'.runtime');
const readJson=p=>JSON.parse(readFileSync(p,'utf8').replace(/^\uFEFF/,''));
const c=readJson(join(runtime,'postgres-admin.json'));for(const value of [c.adminPassword,c.appPassword])if(!/^[0-9a-f]{64}$/.test(value))throw new Error('Invalid provisioning secret');
const admin=new pg.Pool({connectionString:`postgresql://postgres:${c.adminPassword}@127.0.0.1:${c.port}/postgres`});
try{await admin.query(`CREATE ROLE phoneunlock LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '${c.appPassword}'`);
  await admin.query('CREATE DATABASE phoneunlock OWNER phoneunlock');await admin.query('CREATE DATABASE phoneunlock_test OWNER phoneunlock');
}finally{await admin.end();}
const openssl='C:\\Program Files\\Git\\usr\\bin\\openssl.exe';
function run(args){const r=spawnSync(openssl,args,{cwd:runtime,stdio:'pipe'});if(r.status!==0)throw new Error('OpenSSL certificate generation failed');}
run(['req','-x509','-newkey','rsa:3072','-sha256','-days','365','-nodes','-keyout','ca.key','-out','ca.crt','-subj','/CN=WINDOWS-UNLOCK Local Development CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign']);
run(['req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj',`/CN=${c.relayAddress}`]);
writeFileSync(join(runtime,'server.ext'),`basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:${c.relayAddress},IP:127.0.0.1,DNS:localhost\n`);
run(['x509','-req','-in','server.csr','-CA','ca.crt','-CAkey','ca.key','-CAcreateserial','-out','server.crt','-days','30','-sha256','-extfile','server.ext']);
const cert=new X509Certificate(readFileSync(join(runtime,'server.crt')));
const tlsPin='sha256/'+createHash('sha256').update(cert.publicKey.export({type:'spki',format:'der'})).digest('base64');
const relayUrl=`https://${c.relayAddress}:8443`;
writeFileSync(join(runtime,'connection.json'),JSON.stringify({relayUrl,tlsPin},null,2));
writeFileSync(join(runtime,'relay.json'),JSON.stringify({databaseUrl:`postgresql://phoneunlock:${c.appPassword}@127.0.0.1:${c.port}/phoneunlock`,host:c.relayAddress,port:8443,tlsKey:join(runtime,'server.key'),tlsCert:join(runtime,'server.crt')},null,2));
console.log('PostgreSQL databases and development TLS material created. No Windows authentication changes.');
