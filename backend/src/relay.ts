import Fastify, { type FastifyRequest, type FastifyInstance } from 'fastify';
import { randomUUID } from 'node:crypto';
import { ApiError, hash, uuid, now, verified, decode, publicKey, lifetime, fields, strictJson, requireThat } from './protocol.js';
import type { Store, Row } from './store.js';
import type { PushSender } from './push.js';
import { remoteRoutes } from './remote.js';

export function createApp(store: Store, https?: { key: Buffer; cert: Buffer }, push?:PushSender) {
  return configureApp(Fastify(serverOptions(https)),store,push);
}

export function serverOptions(https?: { key: Buffer; cert: Buffer }) {
  return { ...(https ? { https: {...https,minVersion:'TLSv1.2' as const} } : {}), logger: false as const, bodyLimit: 65536, requestTimeout: 10000 };
}

export function configureApp(app:FastifyInstance,store:Store,push?:PushSender) {
  app.removeContentTypeParser('application/json');
  app.addContentTypeParser('application/json', {parseAs:'string'}, (_req, body, done) => {
    try { done(null, strictJson(body as string)); } catch(e) { done(e as Error); }
  });
  app.addHook('onRequest', async req => {
    requireThat(await store.rateLimit(hash(req.ip),2400),'rate_limited',429);
  });
  app.addHook('onSend',async (_req,reply)=>{reply.header('Cache-Control','no-store');reply.header('X-Content-Type-Options','nosniff');});
  app.setErrorHandler((e, _req, reply) => {
    if (e instanceof ApiError) return reply.code(e.status).send({error:e.code});
    if ((e as any).code === '23505') return reply.code(409).send({error:'duplicate'});
    const statusCode = (e as {statusCode?:number}).statusCode;
    const status = statusCode && statusCode < 500 ? statusCode : 503;
    return reply.code(status).send({error:status === 503 ? 'relay_unavailable' : 'invalid_message'});
  });
  const tokenHash = (req: FastifyRequest) => { const h=req.headers.authorization; requireThat(typeof h==='string'&&h.startsWith('Bearer '),'unauthorized',401); const t=h.slice(7); requireThat(/^[A-Za-z0-9_-]{43}$/.test(t),'unauthorized',401); return hash(t); };
  const device = async (req: FastifyRequest, kind: 'windows'|'android', s=store): Promise<Row> => {
    const h=tokenHash(req); const found=(await s.find(kind === 'windows' ? 'windows_devices':'android_devices','tokenHash',h))[0];
    requireThat(found,'unauthorized',401); return (await s.get(kind === 'windows' ? 'windows_devices':'android_devices',found.id))!;
  };
  const session = async (req: FastifyRequest, s=store): Promise<Row> => {
    const id=(req.params as any).id; requireThat(uuid(id)); const r=await s.get('pairing_sessions',id); requireThat(r,'not_found',404);
    const h=tokenHash(req); const w=await s.get('windows_devices',r.windowsDeviceId);
    requireThat(h===r.tokenHash || h===w?.tokenHash,'unauthorized',401);
    requireThat(r.expiresAt > now(),'expired',410); return r;
  };
  const pairing = async (id: string, s=store) => { requireThat(uuid(id)); const p=await s.get('device_pairings',id); requireThat(p?.active,'not_paired',403); return p; };
  app.get('/',async (_req,reply)=>reply.redirect('/health'));
  app.get('/health', async()=>({status:'ok',mode:'desktop-approval-only'}));
  app.post('/v1/pairing-sessions', async req => store.transaction(async s=> {
    const w=await device(req,'windows',s); const b=req.body as any; const p=await verified(b.invitationJws,w.jwk,'pair-invitation');
    fields(p,['sessionId','windowsDeviceId','windowsName','nonce','issuedAt','expiresAt']); lifetime(p,300);
    requireThat(uuid(p.sessionId) && p.windowsDeviceId===w.id && typeof p.windowsName==='string' && p.windowsName.length<=80);
    requireThat(typeof b.tokenHash==='string' && /^[0-9a-f]{64}$/.test(b.tokenHash));
    await s.insert('pairing_sessions',p.sessionId,{id:p.sessionId,windowsDeviceId:w.id,invitationJws:b.invitationJws,tokenHash:b.tokenHash,expiresAt:p.expiresAt,state:'pending'});
    return {sessionId:p.sessionId};
  }));
  app.get('/v1/pairing-sessions/:id', async req=> { const r=await session(req); const {tokenHash:_t,...safe}=r; return safe; });
  app.post('/v1/pairing-sessions/:id/proposal', async req => store.transaction(async s=> {
    const r=await session(req,s); requireThat(tokenHash(req)===r.tokenHash,'forbidden',403); requireThat(r.state==='pending','already_processed',409);
    const b=req.body as any; const raw=decode(b.proposalJws); publicKey(raw.approvalJwk); publicKey(raw.identityJwk);
    const p=await verified(b.proposalJws,raw.approvalJwk,'pair-proposal');
    fields(p,['sessionId','windowsDeviceId','androidDeviceId','phoneName','approvalJwk','identityJwk','invitationHash','tokenHash']);
    requireThat(p.sessionId===r.id && p.windowsDeviceId===r.windowsDeviceId && p.invitationHash===hash(r.invitationJws));
    requireThat(uuid(p.androidDeviceId) && typeof p.phoneName==='string' && p.phoneName.length>0 && p.phoneName.length<=80 && /^[0-9a-f]{64}$/.test(p.tokenHash));
    requireThat(!(await s.get('android_devices',p.androidDeviceId)),'device_exists',409);
    r.proposalJws=b.proposalJws; r.state='proposed'; await s.put('pairing_sessions',r.id,r); return {state:'proposed'};
  }));
  app.post('/v1/pairing-sessions/:id/confirmation', async req=>store.transaction(async s=> {
    const w=await device(req,'windows',s); const r=await session(req,s); requireThat(r.windowsDeviceId===w.id,'forbidden',403); requireThat(r.state==='proposed','already_processed',409);
    const p=await verified((req.body as any).receiptJws,w.jwk,'pair-receipt');
    fields(p,['sessionId','pairingId','windowsDeviceId','androidDeviceId','proposalHash']); const proposal=decode(r.proposalJws);
    requireThat(p.sessionId===r.id && p.windowsDeviceId===w.id && p.androidDeviceId===proposal.androidDeviceId && p.proposalHash===hash(r.proposalJws) && uuid(p.pairingId));
    // Serialize pairing changes on the Windows row; one phone per laptop in this phase.
    requireThat(!(await s.find('device_pairings','windowsDeviceId',w.id)).some(x=>x.active),'already_paired',409);
    await s.insert('android_devices',proposal.androidDeviceId,{id:proposal.androidDeviceId,phoneName:proposal.phoneName,approvalJwk:proposal.approvalJwk,identityJwk:proposal.identityJwk,tokenHash:proposal.tokenHash});
    await s.insert('device_pairings',p.pairingId,{id:p.pairingId,windowsDeviceId:w.id,androidDeviceId:p.androidDeviceId,active:true});
    r.receiptJws=(req.body as any).receiptJws; r.state='confirmed'; await s.put('pairing_sessions',r.id,r); return {state:'confirmed'};
  }));
  app.delete('/v1/device-pairings/:id', async req=>store.transaction(async s=> {
    const w=await device(req,'windows',s); const p=await pairing((req.params as any).id,s); requireThat(p.windowsDeviceId===w.id,'forbidden',403);
    p.active=false; await s.put('device_pairings',p.id,p); const phone=await s.get('android_devices',p.androidDeviceId);
    if(phone) { phone.tokenHash='revoked'; await s.put('android_devices',phone.id,phone); }
    for(const r of await s.find('authentication_requests','pairingId',p.id)) if(r.state==='pending') { r.state='cancelled'; await s.put('authentication_requests',r.id,r); }
    return {state:'revoked'};
  }));
  app.post('/v1/authentication-requests', async req=> {
    const result=await store.transaction(async s=> {
    const w=await device(req,'windows',s); const jws=(req.body as any).requestJws; const p=await verified(jws,w.jwk,'auth-request');
    fields(p,['requestId','windowsDeviceId','androidDeviceId','pairingId','accountBindingId','nonce','issuedAt','expiresAt']); lifetime(p,60);
    requireThat(uuid(p.requestId) && uuid(p.androidDeviceId) && uuid(p.accountBindingId)); const pair=await pairing(p.pairingId,s);
    requireThat(p.windowsDeviceId===w.id && pair.windowsDeviceId===w.id && pair.androidDeviceId===p.androidDeviceId,'forbidden',403);
    requireThat(!(await s.find('authentication_requests','nonce',p.nonce)).length,'nonce_reused',409);
    for(const r of await s.find('authentication_requests','pairingId',pair.id)) if(r.state==='pending') {
      requireThat(r.expiresAt<=now(),'request_pending',409); r.state='expired'; await s.put('authentication_requests',r.id,r);
    }
    await s.insert('authentication_requests',p.requestId,{id:p.requestId,...p,requestJws:jws,state:'pending'}); return {requestId:p.requestId,state:'pending'};
    });
    const r=await store.get('authentication_requests',result.requestId);const a=await store.get('android_devices',r!.androidDeviceId);
    let delivery='not_configured';
    if(push&&a?.fcmToken) {try{await push.send(a.fcmToken,r!.id,r!.expiresAt);delivery='sent';}catch{delivery='failed';}}
    return {...result,pushDelivery:delivery};
  });
  app.get('/v1/authentication-requests/pending', async req=> {
    const phone=await device(req,'android'); const pair=(await store.find('device_pairings','androidDeviceId',phone.id)).find(p=>p.active); requireThat(pair,'not_paired',403);
    const r=(await store.find('authentication_requests','androidDeviceId',phone.id)).find(r=>r.pairingId===pair.id&&r.state==='pending'&&r.expiresAt>now());
    return r ? {requestJws:r.requestJws} : {};
  });
  app.get('/v1/authentication-requests/:id', async req=> {
    const w=await device(req,'windows'); const id=(req.params as any).id; requireThat(uuid(id)); const r=await store.get('authentication_requests',id);
    requireThat(r,'not_found',404); requireThat(r.windowsDeviceId===w.id,'forbidden',403);
    return {state:r.state==='pending'&&r.expiresAt<=now()?'expired':r.state,responseJws:r.responseJws??null};
  });
  app.post('/v1/authentication-requests/:id/responses', async req=>store.transaction(async s=> {
    const phone=await device(req,'android',s); const id=(req.params as any).id; requireThat(uuid(id)); const r=await s.get('authentication_requests',id);
    requireThat(r,'not_found',404); requireThat(r.androidDeviceId===phone.id,'forbidden',403); requireThat(r.state==='pending','already_processed',409); requireThat(r.expiresAt>now(),'expired',410);
    await pairing(r.pairingId,s); const jws=(req.body as any).responseJws; const raw=decode(jws); requireThat(raw.decision==='approve'||raw.decision==='deny');
    const p=await verified(jws,raw.decision==='approve'?phone.approvalJwk:phone.identityJwk,'auth-response');
    fields(p,['requestId','pairingId','windowsDeviceId','androidDeviceId','challengeHash','decision']);
    requireThat(p.requestId===id&&p.pairingId===r.pairingId&&p.windowsDeviceId===r.windowsDeviceId&&p.androidDeviceId===phone.id&&p.challengeHash===hash(r.requestJws),'binding_mismatch');
    r.responseJws=jws; r.state='response_received'; await s.put('authentication_requests',id,r); return {state:'response_received'};
  }));
  app.post('/v1/authentication-requests/:id/cancel', async req=>store.transaction(async s=> {
    const w=await device(req,'windows',s); const p=await verified((req.body as any).cancelJws,w.jwk,'auth-cancel'); fields(p,['requestId']);
    const id=(req.params as any).id; requireThat(uuid(id)&&p.requestId===id); const r=await s.get('authentication_requests',id); requireThat(r&&r.windowsDeviceId===w.id,'not_found',404);
    requireThat(r.state==='pending','already_processed',409); r.state='cancelled'; await s.put('authentication_requests',id,r); return {state:'cancelled'};
  }));
  app.post('/v1/authentication-events', async req=>store.transaction(async s=> {
    const w=await device(req,'windows',s); const p=await verified((req.body as any).eventJws,w.jwk,'auth-event'); fields(p,['requestId','pairingId','result','timestamp','snapshotPath']);
    const r=await s.get('authentication_requests',p.requestId); requireThat(r&&r.windowsDeviceId===w.id&&r.pairingId===p.pairingId);
    requireThat(['approved','denied','expired','cancelled','failed'].includes(p.result)&&Number.isSafeInteger(p.timestamp)&&p.snapshotPath===null);
    const id=randomUUID(); await s.insert('authentication_events',id,{id,...p,eventJws:(req.body as any).eventJws}); return {recorded:true};
  }));
  app.post('/v1/android/push-token',async req=>store.transaction(async s=>{
    const a=await device(req,'android',s);const p=await verified((req.body as any).registrationJws,a.identityJwk,'push-registration');
    fields(p,['androidDeviceId','pairingId','token','nonce','issuedAt','expiresAt']);lifetime(p,300);
    const pair=await pairing(p.pairingId,s);requireThat(p.androidDeviceId===a.id&&pair.androidDeviceId===a.id,'forbidden',403);
    requireThat(typeof p.token==='string'&&p.token.length>20&&p.token.length<=4096&&/^[A-Za-z0-9_:\-]+$/.test(p.token));
    requireThat(!a.pushIssuedAt||p.issuedAt>=a.pushIssuedAt,'stale_registration',409);
    a.fcmToken=p.token;a.pushIssuedAt=p.issuedAt;await s.put('android_devices',a.id,a);return {registered:!!push};
  }));
  remoteRoutes(app,store,device);
  return app;
}
