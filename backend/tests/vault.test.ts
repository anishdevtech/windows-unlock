import {test,type TestContext} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID,generateKeyPairSync} from 'node:crypto';
import {generateKeyPair,exportJWK,CompactSign} from 'jose';
import {createApp} from '../src/relay.js';
import {MemoryStore,PgStore,type Store} from '../src/store.js';
import {Pool} from 'pg';
import {readFileSync} from 'node:fs';
import {hash,now} from '../src/protocol.js';
const key=async()=>{const k=await generateKeyPair('ES256',{extractable:true});return {...k,jwk:await exportJWK(k.publicKey)};};
const sign=(k:Awaited<ReturnType<typeof key>>,p:object)=>new CompactSign(Buffer.from(JSON.stringify(p))).setProtectedHeader({alg:'ES256',typ:'phoneunlock+jws'}).sign(k.privateKey);
const m=<T extends object>(type:string,p:T)=>({v:1,purpose:'password-unlock',type,...p});
const nonce=()=>randomBytes(32).toString('base64url');
const rsa=generateKeyPairSync('rsa',{modulusLength:2048}).publicKey.export({format:'jwk'});
async function fixture(t:TestContext){
  let store:Store=new MemoryStore(),pool:Pool|undefined;const db=process.env.PHONEUNLOCK_TEST_DATABASE_URL;
  if(db){assert.match(new URL(db).pathname,/_test$/,'Refuse to clear a non-test database');pool=new Pool({connectionString:db});for(const name of ['001_initial.sql','002_remote.sql','003_diagnostics.sql','004_vault.sql'])await pool.query(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));await pool.query('TRUNCATE windows_devices,android_devices,device_pairings,vault_requests,authentication_events,diagnostic_logs,rate_limits');store=new PgStore(pool);}
  const app=createApp(store);t.after(async()=>{await app.close();await pool?.end();});
  const root=await key(),machine=await key(),approval=await key(),identity=await key();
  const wid=randomUUID(),aid=randomUUID(),pair=randomUUID(),wt=nonce(),at=nonce();
  await store.put('windows_devices',wid,{id:wid,jwk:root.jwk,tokenHash:hash(wt)});
  await store.put('android_devices',aid,{id:aid,approvalJwk:approval.jwk,identityJwk:identity.jwk,tokenHash:hash(at)});
  await store.put('device_pairings',pair,{id:pair,windowsDeviceId:wid,androidDeviceId:aid,active:true});
  const call=(method:string,url:string,token:string,payload?:object)=>app.inject({method:method as any,url,headers:{authorization:`Bearer ${token}`},payload});
  const d=m('vault-delegation',{vaultId:randomUUID(),windowsDeviceId:wid,androidDeviceId:aid,pairingId:pair,accountBindingId:randomUUID(),windowsAccountSid:'S-1-5-21-1-2-3-1001',loginName:'MicrosoftAccount\\test@example.com',machineJwk:machine.jwk});
  const delegationJws=await sign(root,d);
  const request=async(enroll=true,overrides:object={},signer=enroll?root:machine)=>{
    const p=m(enroll?'vault-enroll':'vault-unlock',{requestId:randomUUID(),nonce:nonce(),issuedAt:now(),expiresAt:now()+(enroll?300:60),delegationJws,...(!enroll?{sessionId:1,usageScenario:1,ephemeralJwk:rsa,wrappedKey:randomBytes(256).toString('base64url')}:{ }),...overrides});
    const token=await sign(signer,p);return {p,token,send:()=>call('POST','/v1/vault-requests',wt,{requestJws:token})};
  };
  const response=async(r:Awaited<ReturnType<typeof request>>,decision='approve',overrides:object={},signer=r.p.type==='vault-enroll'&&decision==='approve'?approval:identity)=>sign(signer,m(r.p.type==='vault-enroll'?'vault-enrolled':'vault-response',{requestId:r.p.requestId,challengeHash:hash(r.token),decision,...(decision==='approve'?r.p.type==='vault-enroll'?{phoneJwk:rsa}:{wrappedKey:randomBytes(256).toString('base64url')}:{ }),...overrides}));
  return {store,call,root,machine,approval,identity,wid,aid,pair,wt,at,d,delegationJws,request,response};
}
test('vault enrollment requires paired root delegation and biometric approval key',async t=>{
  const f=await fixture(t),r=await f.request();assert.equal((await r.send()).statusCode,200);
  assert.equal((await f.call('GET','/v1/vault-requests/pending',f.at)).json().requestJws,r.token);
  const url=`/v1/vault-requests/${r.p.requestId}/responses`;
  assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r,'approve',{},f.identity)})).statusCode,400);
  assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r,'approve',{phoneJwk:{...rsa,d:'private'}})})).statusCode,400);
  const responseJws=await f.response(r);assert.equal((await f.call('POST',url,f.at,{responseJws})).statusCode,200);
  assert.equal((await f.call('POST',url,f.at,{responseJws})).statusCode,409);
  assert.equal((await f.call('GET',`/v1/vault-requests/${r.p.requestId}`,f.wt)).json().state,'approved');
});
test('vault request rejects relay forgery, altered delegation, cross pairing and secrets',async t=>{
  const f=await fixture(t);
  const badDelegate=await sign(f.root,{...f.d,androidDeviceId:randomUUID()});
  for(const r of [await f.request(false,{},await key()),await f.request(true,{delegationJws:badDelegate}),await f.request(true,{password:'never accept this'}),await f.request(false,{ephemeralJwk:{...rsa,d:'private'}}),await f.request(false,{sessionId:0}),await f.request(false,{wrappedKey:'wrong'})])assert.equal((await r.send()).statusCode,400);
  assert.equal((await f.call('POST','/v1/vault-requests',f.at,{requestJws:(await f.request()).token})).statusCode,401);
  assert.equal((await f.call('GET','/v1/vault-requests/pending',nonce())).statusCode,401);
});
test('vault nonce reuse and cancelled or expired approval fail closed',async t=>{
  const f=await fixture(t),r=await f.request(false);assert.equal((await r.send()).statusCode,200);
  assert.equal((await (await f.request(false)).send()).statusCode,409);
  const cancelJws=await sign(f.machine,m('vault-cancel',{requestId:r.p.requestId,challengeHash:hash(r.token)}));
  const url=`/v1/vault-requests/${r.p.requestId}`;
  assert.equal((await f.call('POST',url+'/cancel',f.wt,{cancelJws})).statusCode,200);
  assert.equal((await f.call('POST',url+'/responses',f.at,{responseJws:await f.response(r)})).statusCode,409);
  assert.equal((await (await f.request(false,{nonce:r.p.nonce})).send()).statusCode,409);
  for(const overrides of [{issuedAt:now()-61,expiresAt:now()-1},{issuedAt:now()+60,expiresAt:now()+120},{expiresAt:now()+61}])assert.ok((await (await f.request(false,overrides)).send()).statusCode>=400);
  const fresh=await f.request(false);await fresh.send();const row=(await f.store.get('vault_requests',fresh.p.requestId))!;row.expiresAt=now()-1;await f.store.put('vault_requests',row.id,row);
  assert.equal((await f.call('POST',`/v1/vault-requests/${row.id}/responses`,f.at,{responseJws:await f.response(fresh)})).statusCode,410);
});
test('vault release is bound to exact challenge, terminal once, and inaccessible after revocation',async t=>{
  const f=await fixture(t),r=await f.request(false);await r.send();const url=`/v1/vault-requests/${r.p.requestId}`;
  for(const changes of [{challengeHash:'0'.repeat(64)},{requestId:randomUUID()},{purpose:'desktop-approval'},{wrappedKey:'invalid'},{password:'not allowed'}])assert.equal((await f.call('POST',url+'/responses',f.at,{responseJws:await f.response(r,'approve',changes)})).statusCode,400);
  const responseJws=await f.response(r);const results=await Promise.all([1,2].map(()=>f.call('POST',url+'/responses',f.at,{responseJws})));
  assert.deepEqual(results.map(r=>r.statusCode).sort(),[200,409]);
  const pair=(await f.store.get('device_pairings',f.pair))!;pair.active=false;await f.store.put('device_pairings',f.pair,pair);
  assert.equal((await f.call('GET',url,f.wt)).statusCode,403);
  assert.equal((await (await f.request(false)).send()).statusCode,403);
});
test('identity-key denial closes vault enrollment without releasing keys',async t=>{
  const f=await fixture(t),r=await f.request();await r.send();
  assert.equal((await f.call('POST',`/v1/vault-requests/${r.p.requestId}/responses`,f.at,{responseJws:await f.response(r,'deny')})).statusCode,200);
  assert.equal((await f.call('GET',`/v1/vault-requests/${r.p.requestId}`,f.wt)).json().state,'denied');
});
