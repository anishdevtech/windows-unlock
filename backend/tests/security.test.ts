import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, CompactSign, type JWK } from 'jose';
import { Pool } from 'pg';
import { readFileSync } from 'node:fs';
import { createApp } from '../src/relay.js';
import { MemoryStore, PgStore, type Store } from '../src/store.js';
import { hash, now, strictJson, publicKey } from '../src/protocol.js';

const transport=()=>randomBytes(32).toString('base64url');
const message=<T extends Record<string,unknown>>(type:string, fields:T)=>({v:1,purpose:'desktop-approval',type,...fields});
const key=async()=>{const k=await generateKeyPair('ES256',{extractable:true});const jwk=await exportJWK(k.publicKey);return {...k,jwk};};
const sign=async(k:Awaited<ReturnType<typeof key>>,p:Record<string,unknown>)=>new CompactSign(Buffer.from(JSON.stringify(p))).setProtectedHeader({alg:'ES256',typ:'phoneunlock+jws'}).sign(k.privateKey);
async function fixture(t:TestContext,push?:import('../src/push.js').PushSender){
  let store:Store=new MemoryStore();let pool:Pool|undefined;
  const db=process.env.PHONEUNLOCK_TEST_DATABASE_URL;
  if(db){assert.match(new URL(db).pathname,/_test$/,'Refuse to clear a non-test database');pool=new Pool({connectionString:db});
    await pool.query(readFileSync(new URL('../migrations/001_initial.sql',import.meta.url),'utf8'));
    await pool.query(readFileSync(new URL('../migrations/002_remote.sql',import.meta.url),'utf8'));
    await pool.query('TRUNCATE users,windows_devices,android_devices,device_pairings,pairing_sessions,authentication_requests,authentication_events,remote_offers,remote_commands,camera_frames,rate_limits');store=new PgStore(pool);
  }
  const app=createApp(store,undefined,push);t.after(async()=>{await app.close();await pool?.end();});
  const w=await key(),approval=await key(),identity=await key();const wid=randomUUID(),aid=randomUUID(),pair=randomUUID(),sid=randomUUID();const wt=transport(),at=transport(),pt=transport();
  await store.put('windows_devices',wid,{id:wid,name:'Test laptop',jwk:w.jwk,tokenHash:hash(wt)});
  const call=(method:string,url:string,token:string,payload?:unknown)=>app.inject({method:method as any,url,headers:{authorization:`Bearer ${token}`},...(payload?{payload:payload as any}:{})});
  const invitationJws=await sign(w,message('pair-invitation',{sessionId:sid,windowsDeviceId:wid,windowsName:'Test laptop',nonce:transport(),issuedAt:now(),expiresAt:now()+300}));
  assert.equal((await call('POST','/v1/pairing-sessions',wt,{invitationJws,tokenHash:hash(pt)})).statusCode,200);
  const proposalJws=await sign(approval,message('pair-proposal',{sessionId:sid,windowsDeviceId:wid,androidDeviceId:aid,phoneName:'Test phone',approvalJwk:approval.jwk,identityJwk:identity.jwk,invitationHash:hash(invitationJws),tokenHash:hash(at)}));
  assert.equal((await call('POST',`/v1/pairing-sessions/${sid}/proposal`,pt,{proposalJws})).statusCode,200);
  const receiptJws=await sign(w,message('pair-receipt',{sessionId:sid,pairingId:pair,windowsDeviceId:wid,androidDeviceId:aid,proposalHash:hash(proposalJws)}));
  assert.equal((await call('POST',`/v1/pairing-sessions/${sid}/confirmation`,wt,{receiptJws})).statusCode,200);
  const challenge=async(overrides:Record<string,unknown>={})=>{
    const p=message('auth-request',{requestId:randomUUID(),windowsDeviceId:wid,androidDeviceId:aid,pairingId:pair,accountBindingId:randomUUID(),nonce:transport(),issuedAt:now(),expiresAt:now()+60,...overrides});const token=await sign(w,p);
    return {p,token,send:()=>call('POST','/v1/authentication-requests',wt,{requestJws:token})};
  };
  const response=async(r:Awaited<ReturnType<typeof challenge>>,decision='approve',overrides:Record<string,unknown>={},signer=decision==='approve'?approval:identity)=>sign(signer,message('auth-response',{requestId:r.p.requestId,pairingId:pair,windowsDeviceId:wid,androidDeviceId:aid,challengeHash:hash(r.token),decision,...overrides}));
  return {store,app,call,w,approval,identity,wid,aid,pair,sid,wt,at,pt,challenge,response};
}
test('bilateral pairing and valid approval delivery; duplicate is rejected',async t=>{
  const f=await fixture(t),r=await f.challenge();assert.equal((await r.send()).statusCode,200);
  assert.equal((await f.call('GET','/v1/authentication-requests/pending',f.at)).json().requestJws,r.token);
  const responseJws=await f.response(r);const url=`/v1/authentication-requests/${r.p.requestId}/responses`;
  assert.equal((await f.call('POST',url,f.at,{responseJws})).statusCode,200);assert.equal((await f.call('POST',url,f.at,{responseJws})).statusCode,409);
  assert.equal((await f.call('GET',`/v1/authentication-requests/${r.p.requestId}`,f.wt)).json().state,'response_received');
});
test('denial uses identity key; that key cannot approve',async t=>{
  const f=await fixture(t),r=await f.challenge();await r.send();const url=`/v1/authentication-requests/${r.p.requestId}/responses`;
  assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r,'approve',{},f.identity)})).statusCode,400);
  assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r,'deny')})).statusCode,200);
});
test('Windows unlock purpose binds session and rejects desktop approval substitution',async t=>{
  const f=await fixture(t),r=await f.challenge({purpose:'windows-unlock',windowsAccountSid:'S-1-5-21-1-2-3-1001',sessionId:1,usageScenario:1,existingLogonId:'0000000000001234'});
  assert.equal((await r.send()).statusCode,200);const url=`/v1/authentication-requests/${r.p.requestId}/responses`;
  assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r)})).statusCode,400);
  assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r,'approve',{purpose:'windows-unlock'})})).statusCode,200);
});
test('Windows unlock requests require exact account/session context',async t=>{
  const f=await fixture(t);
  for(const bad of [{},{windowsAccountSid:'S-1-5-18',sessionId:1,usageScenario:1,existingLogonId:'0000000000001234'},{windowsAccountSid:'S-1-5-21-1-2-3-1001',sessionId:0,usageScenario:1,existingLogonId:'0000000000001234'}])
    assert.equal((await (await f.challenge({purpose:'windows-unlock',...bad})).send()).statusCode,400);
});
test('wrong binding and fake signature cannot consume pending request',async t=>{
  const f=await fixture(t),r=await f.challenge();await r.send();const url=`/v1/authentication-requests/${r.p.requestId}/responses`;
  for(const override of [{challengeHash:'0'.repeat(64)},{requestId:randomUUID()},{androidDeviceId:randomUUID()},{pairingId:randomUUID()},{purpose:'windows-logon'}])
    assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r,'approve',override)})).statusCode,400);
  assert.equal((await f.call('POST',url,f.at,{responseJws:await f.response(r,'approve',{},await key())})).statusCode,400);
  assert.equal((await f.call('GET',`/v1/authentication-requests/${r.p.requestId}`,f.wt)).json().state,'pending');
});
test('expired, future and excessive-lifetime requests fail',async t=>{
  const f=await fixture(t);
  for(const o of [{issuedAt:now()-61,expiresAt:now()-1},{issuedAt:now()+60,expiresAt:now()+120},{expiresAt:now()+61}]) assert.ok((await (await f.challenge(o)).send()).statusCode>=400);
});
test('single pending request, cancellation and nonce replay rejection',async t=>{
  const f=await fixture(t),r=await f.challenge();await r.send();assert.equal((await (await f.challenge()).send()).statusCode,409);
  const cancelJws=await sign(f.w,message('auth-cancel',{requestId:r.p.requestId}));assert.equal((await f.call('POST',`/v1/authentication-requests/${r.p.requestId}/cancel`,f.wt,{cancelJws})).statusCode,200);
  assert.equal((await f.call('POST',`/v1/authentication-requests/${r.p.requestId}/responses`,f.at,{responseJws:await f.response(r)})).statusCode,409);
  assert.equal((await (await f.challenge({nonce:r.p.nonce})).send()).statusCode,409);
});
test('concurrent duplicate approvals consume exactly once',async t=>{
  const f=await fixture(t),r=await f.challenge();await r.send();const responseJws=await f.response(r);
  const results=await Promise.all([1,2].map(()=>f.call('POST',`/v1/authentication-requests/${r.p.requestId}/responses`,f.at,{responseJws})));
  assert.deepEqual(results.map(x=>x.statusCode).sort(),[200,409]);
});
test('revocation and stolen/incorrect token cannot authorize',async t=>{
  const f=await fixture(t),r=await f.challenge();assert.equal((await f.call('POST','/v1/authentication-requests',f.at,{requestJws:r.token})).statusCode,401);
  await r.send();assert.equal((await f.call('DELETE',`/v1/device-pairings/${f.pair}`,f.wt)).statusCode,200);
  assert.equal((await f.call('POST',`/v1/authentication-requests/${r.p.requestId}/responses`,f.at,{responseJws:await f.response(r)})).statusCode,401);
  assert.equal((await f.call('GET','/v1/authentication-requests/pending',transport())).statusCode,401);
});
test('pairing proposal is single-use and secret hash is not returned',async t=>{
  const f=await fixture(t);const r=await f.call('GET',`/v1/pairing-sessions/${f.sid}`,f.pt);assert.equal(r.json().tokenHash,undefined);
  assert.equal((await f.call('POST',`/v1/pairing-sessions/${f.sid}/proposal`,f.pt,{proposalJws:'x'})).statusCode,409);
});
test('strict parser, nested duplicate keys and oversized input',()=>{
  assert.throws(()=>strictJson('{"a":1,"a":2}'));assert.throws(()=>strictJson('{"x":{"a":1,"\\u0061":2}}'));
  assert.throws(()=>strictJson('{"x":"'+'a'.repeat(65536)+'"}'));assert.deepEqual(strictJson('{"x":[{"a":1},{"a":2}]}'),{x:[{a:1},{a:2}]});
});
test('public-key-only input rejects private-key field',async t=>{
  const f=await fixture(t);assert.throws(()=>publicKey({...f.approval.jwk,d:'not-allowed'}));
  const privateJwk={...f.approval.jwk,d:'not-allowed'};
  // Memory store is test infrastructure; exercise the SQL CHECK on native PostgreSQL.
  if(process.env.PHONEUNLOCK_TEST_DATABASE_URL)
    await assert.rejects(()=>f.store.insert('android_devices',randomUUID(),{id:randomUUID(),approvalJwk:privateJwk,identityJwk:f.identity.jwk}));
});

async function remote(f:Awaited<ReturnType<typeof fixture>>,actions=['lock','camera-start','camera-stop'],overrides:Record<string,unknown>={}) {
  const p=message('remote-offer',{offerId:randomUUID(),windowsDeviceId:f.wid,androidDeviceId:f.aid,pairingId:f.pair,nonce:transport(),issuedAt:now(),expiresAt:now()+60,actions,...overrides});
  const token=await sign(f.w,p);
  const send=()=>f.call('POST','/v1/remote/offers',f.wt,{offerJws:token});
  const command=async(action='lock',overrides:Record<string,unknown>={},signer=f.approval)=>sign(signer,message('remote-command',{commandId:randomUUID(),offerId:p.offerId,windowsDeviceId:f.wid,androidDeviceId:f.aid,pairingId:f.pair,offerHash:hash(token),action,viewerJwk:null,...overrides}));
  return {p,token,send,command};
}
test('remote commands require fresh biometric-key signature, binding and enabled action',async t=>{
  const f=await fixture(t),r=await remote(f);assert.equal((await r.send()).statusCode,200);
  assert.equal((await f.call('GET','/v1/remote/offer',f.at)).json().offerJws,r.token);
  for(const jws of [await r.command('lock',{},f.identity),await r.command('restart'),await r.command('lock',{offerHash:'0'.repeat(64)}),await r.command('lock',{pairingId:randomUUID()})])
    assert.ok((await f.call('POST','/v1/remote/commands',f.at,{commandJws:jws})).statusCode>=400);
  const commandJws=await r.command();assert.equal((await f.call('POST','/v1/remote/commands',f.at,{commandJws})).statusCode,200);
  assert.equal((await f.call('POST','/v1/remote/commands',f.at,{commandJws})).statusCode,409);
});
test('remote duplicate race consumes one offer and expired/superseded offers fail',async t=>{
  const f=await fixture(t),r=await remote(f);await r.send();const commandJws=await r.command();
  const results=await Promise.all([1,2].map(()=>f.call('POST','/v1/remote/commands',f.at,{commandJws})));
  assert.deepEqual(results.map(r=>r.statusCode).sort(),[200,409]);
  const old=await remote(f);await old.send();const next=await remote(f);await next.send();
  assert.equal((await f.call('POST','/v1/remote/commands',f.at,{commandJws:await old.command()})).statusCode,409);
  assert.ok((await (await remote(f,['lock'],{issuedAt:now()-61,expiresAt:now()-1})).send()).statusCode>=400);
});
test('camera relay validates encrypted frames, recipient, counter and revocation',async t=>{
  const f=await fixture(t),r=await remote(f);await r.send();
  const rsa=await generateKeyPair('RSA-OAEP-256',{modulusLength:2048,extractable:true});const full=await exportJWK(rsa.publicKey);const viewerJwk={kty:full.kty,n:full.n,e:full.e};
  const commandJws=await r.command('camera-start',{viewerJwk});const c=(await f.call('POST','/v1/remote/commands',f.at,{commandJws})).json();assert.ok(c.commandId);
  const frame={sequence:1,iv:randomBytes(12).toString('base64url'),wrappedKey:randomBytes(256).toString('base64url'),ciphertext:randomBytes(100).toString('base64url')};const url=`/v1/camera/${c.commandId}/frame`;
  assert.equal((await f.call('POST',url,f.at,frame)).statusCode,401);
  assert.equal((await f.call('POST',url,f.wt,{...frame,plaintext:'not permitted'})).statusCode,400);
  assert.equal((await f.call('POST',url,f.wt,frame)).statusCode,200);assert.equal((await f.call('POST',url,f.wt,frame)).statusCode,409);
  assert.deepEqual((await f.call('GET',url,f.at)).json(),frame);
  assert.equal((await f.call('GET',url,f.wt)).statusCode,401);
  await f.call('DELETE',`/v1/device-pairings/${f.pair}`,f.wt);
  assert.equal((await f.call('GET',url,f.at)).statusCode,401);
});
test('camera key rejects private RSA material and invalid recipient',async t=>{
  const f=await fixture(t),r=await remote(f);await r.send();
  for(const viewerJwk of [{kty:'RSA',n:'AA',e:'AQAB'},{kty:'RSA',n:'AA',e:'AQAB',d:'secret'},null])
    assert.equal((await f.call('POST','/v1/remote/commands',f.at,{commandJws:await r.command('camera-start',{viewerJwk})})).statusCode,400);
});
test('FCM registration requires identity-key proof; push failure preserves committed request',async t=>{
  let invoked=0;const f=await fixture(t,{async send(){invoked++;throw new Error('simulated FCM unavailable');}});
  const registration=message('push-registration',{androidDeviceId:f.aid,pairingId:f.pair,token:'test-fcm-address-abcdefghijklmnopqrstuvwxyz',nonce:transport(),issuedAt:now(),expiresAt:now()+300});
  assert.equal((await f.call('POST','/v1/android/push-token',f.at,{registrationJws:await sign(f.w,registration)})).statusCode,400);
  assert.equal((await f.call('POST','/v1/android/push-token',f.at,{registrationJws:await sign(f.identity,registration)})).statusCode,200);
  const r=await f.challenge();const result=await r.send();assert.equal(result.statusCode,200);assert.equal(result.json().pushDelivery,'failed');assert.equal(invoked,1);
  assert.equal((await f.call('GET','/v1/authentication-requests/pending',f.at)).json().requestJws,r.token);
});
