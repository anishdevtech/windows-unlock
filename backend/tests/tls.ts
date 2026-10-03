import {readFileSync,writeFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {createApp} from '../src/relay.js';
import {MemoryStore} from '../src/store.js';
const [exe,relayConfig,connectionFile,fixtureFile]=process.argv.slice(2);
if(!exe||!relayConfig||!connectionFile||!fixtureFile)throw new Error('tls <http_tests.exe> <relay.json> <connection.json> <fixture-output>');
const config=JSON.parse(readFileSync(relayConfig,'utf8')),connection=JSON.parse(readFileSync(connectionFile,'utf8'));
const app=createApp(new MemoryStore(),{key:readFileSync(config.tlsKey),cert:readFileSync(config.tlsCert)});let requests=0;
app.addHook('onRequest',async()=>{requests++;});
try{await app.listen({host:'127.0.0.1',port:0});const address=app.server.address();if(!address||typeof address==='string')throw new Error('Missing address');
  writeFileSync(fixtureFile,JSON.stringify({relayUrl:`https://127.0.0.1:${address.port}`,tlsPin:connection.tlsPin}));
  // Async spawn keeps the TLS server responsive while the C++ test is running.
  const code=await new Promise<number|null>((resolve,reject)=>{const child=spawn(exe,[fixtureFile],{stdio:'inherit'});child.on('error',reject);child.on('exit',resolve);});
  if(code!==0||requests!==1)throw new Error('TLS checks failed or pin-mismatched request reached HTTP application');
  console.log('Incorrect certificate pin blocked before HTTP Authorization/body transmission');
}finally{await app.close();}
