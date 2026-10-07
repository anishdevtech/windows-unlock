import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Store, Row } from './store.js';
import type { PushSender } from './push.js';
import { decode, verified, fields, publicKey, lifetime, uuid, hash, now, requireThat } from './protocol.js';
import {validEntry} from './diagnostics.js';
import {randomUUID} from 'node:crypto';

export function rsaPublic(j:any) {
  requireThat(j&&Object.keys(j).sort().join(',')==='e,kty,n'&&j.kty==='RSA'&&j.e==='AQAB','invalid_rsa_key');
  requireThat(typeof j.n==='string'&&/^[A-Za-z0-9_-]+$/.test(j.n),'invalid_rsa_key');
  const n=Buffer.from(j.n,'base64url');
  requireThat(n.length===256&&n[0]!>=128&&n.toString('base64url')===j.n,'invalid_rsa_key');
}
function wrapped(s:any) { requireThat(typeof s==='string'&&Buffer.from(s,'base64url').length===256&&Buffer.from(s,'base64url').toString('base64url')===s,'invalid_wrapped_key'); }
export async function delegation(token:string,windows:Row,pair:Row) {
  const d=await verified(token,windows.jwk,'vault-delegation');
  fields(d,['vaultId','windowsDeviceId','androidDeviceId','pairingId','accountBindingId','windowsAccountSid','loginName','machineJwk']);
  requireThat(d.purpose==='password-unlock'&&uuid(d.vaultId)&&uuid(d.accountBindingId)&&d.windowsDeviceId===windows.id&&d.androidDeviceId===pair.androidDeviceId&&d.pairingId===pair.id,'binding_mismatch');
  requireThat(typeof d.windowsAccountSid==='string'&&/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(d.windowsAccountSid),'invalid_account');
  requireThat(typeof d.loginName==='string'&&d.loginName.length>0&&d.loginName.length<=256&&!/[\x00-\x1f]/.test(d.loginName),'invalid_account');
  publicKey(d.machineJwk); return d;
}
export function vaultRoutes(app:FastifyInstance,store:Store,device:(q:FastifyRequest,k:'windows'|'android',s?:Store)=>Promise<Row>,push?:PushSender) {
  app.post('/v1/vault-diagnostics',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s),body=req.body as any;requireThat(body&&Object.keys(body).sort().join(',')==='batchJws,delegationJws');
    const raw=decode(body.delegationJws);requireThat(uuid(raw.pairingId));const pair=await s.get('device_pairings',raw.pairingId);requireThat(pair?.active&&pair.windowsDeviceId===w.id,'not_paired',403);
    const d=await delegation(body.delegationJws,w,pair),p=await verified(body.batchJws,d.machineJwk,'diagnostic-batch');fields(p,['batchId','windowsDeviceId','issuedAt','expiresAt','entries']);
    requireThat(p.purpose==='password-unlock'&&uuid(p.batchId)&&p.windowsDeviceId===w.id&&Number.isSafeInteger(p.issuedAt)&&Number.isSafeInteger(p.expiresAt)&&p.issuedAt<=now()+30&&p.expiresAt>now()&&p.expiresAt-p.issuedAt<=300&&p.expiresAt>p.issuedAt);
    requireThat(Array.isArray(p.entries)&&p.entries.length>0&&p.entries.length<=50);p.entries.forEach(validEntry);
    for(const entry of p.entries){const existing=await s.get('diagnostic_logs',entry.id);if(existing){requireThat(existing.windowsDeviceId===w.id);continue;}await s.insert('diagnostic_logs',entry.id,{...entry,windowsDeviceId:w.id,receivedAt:now()});}
    await s.pruneLogs(w.id);return {recorded:p.entries.length,retentionDays:7};
  }));
  app.post('/v1/vault-requests',async req=>{
    const result=await store.transaction(async s=>{
      const w=await device(req,'windows',s); const body=req.body as any;
      requireThat(body&&Object.keys(body).join(',')==='requestJws');
      const raw=decode(body.requestJws); requireThat(['vault-enroll','vault-unlock'].includes(raw.type));
      const untrusted=decode(raw.delegationJws); requireThat(uuid(untrusted.pairingId));
      const pair=await s.get('device_pairings',untrusted.pairingId); requireThat(pair?.active&&pair.windowsDeviceId===w.id,'not_paired',403);
      const d=await delegation(raw.delegationJws,w,pair);
      const p=await verified(body.requestJws,raw.type==='vault-enroll'?w.jwk:d.machineJwk,raw.type);
      fields(p,['requestId','nonce','issuedAt','expiresAt','delegationJws',...(p.type==='vault-unlock'?['sessionId','usageScenario','ephemeralJwk','wrappedKey']:[])]);
      requireThat(p.purpose==='password-unlock'&&uuid(p.requestId)); lifetime(p,p.type==='vault-enroll'?300:60);
      if(p.type==='vault-unlock') {
        requireThat(Number.isInteger(p.sessionId)&&p.sessionId>0&&[1,2].includes(p.usageScenario)); rsaPublic(p.ephemeralJwk); wrapped(p.wrappedKey);
      }
      requireThat(!(await s.find('vault_requests','nonce',p.nonce)).length,'nonce_reused',409);
      requireThat(!(await s.pending('vault_requests','windowsDeviceId',w.id)).length,'request_pending',409);
      const row:Row={id:p.requestId,...p,windowsDeviceId:w.id,androidDeviceId:pair.androidDeviceId,pairingId:pair.id,state:'pending',requestJws:body.requestJws};
      await s.insert('vault_requests',p.requestId,row);const eventId=randomUUID();await s.insert('authentication_events',eventId,{id:eventId,requestId:p.requestId,windowsDeviceId:w.id,androidDeviceId:pair.androidDeviceId,timestamp:now(),result:'vault_request_created',snapshotPath:null});return row;
    });
    const phone=await store.get('android_devices',result.androidDeviceId); let pushDelivery='not_configured';
    if(push&&phone?.fcmToken){try{await push.send(phone.fcmToken,result.id,result.expiresAt);pushDelivery='sent';}catch{pushDelivery='failed';}}
    return {requestId:result.id,state:'pending',pushDelivery};
  });
  app.get('/v1/vault-requests/pending',async req=>{
    const a=await device(req,'android'); const pair=(await store.find('device_pairings','androidDeviceId',a.id)).find(p=>p.active); requireThat(pair,'not_paired',403);
    const r=(await store.pending('vault_requests','androidDeviceId',a.id)).find(r=>r.pairingId===pair.id);
    return r?{requestJws:r.requestJws}:{};
  });
  app.get('/v1/vault-requests/:id',async req=>{
    const w=await device(req,'windows'); const id=(req.params as any).id; requireThat(uuid(id)); const r=await store.get('vault_requests',id);
    requireThat(r&&r.windowsDeviceId===w.id,'not_found',404);
    const pair=await store.get('device_pairings',r.pairingId);requireThat(pair?.active,'not_paired',403);
    return {state:r.state==='pending'&&r.expiresAt<=now()?'expired':r.state,responseJws:r.responseJws??null};
  });
  app.post('/v1/vault-requests/:id/responses',async req=>store.transaction(async s=>{
    const a=await device(req,'android',s); const id=(req.params as any).id; requireThat(uuid(id)); const r=await s.get('vault_requests',id);
    requireThat(r&&r.androidDeviceId===a.id,'not_found',404); const pair=await s.get('device_pairings',r.pairingId); requireThat(pair?.active,'not_paired',403);
    requireThat(r.state==='pending','already_processed',409); requireThat(r.expiresAt>now(),'expired',410);
    const body=req.body as any; requireThat(body&&Object.keys(body).join(',')==='responseJws'); const raw=decode(body.responseJws);
    requireThat(['approve','deny'].includes(raw.decision));
    const enroll=r.type==='vault-enroll'; const p=await verified(body.responseJws,enroll&&raw.decision==='approve'?a.approvalJwk:a.identityJwk,enroll?'vault-enrolled':'vault-response');
    fields(p,['requestId','challengeHash','decision',...(p.decision==='approve'?[enroll?'phoneJwk':'wrappedKey']:[])]);
    requireThat(p.purpose==='password-unlock'&&p.requestId===id&&p.challengeHash===hash(r.requestJws),'binding_mismatch');
    if(p.decision==='approve'){if(enroll)rsaPublic(p.phoneJwk);else wrapped(p.wrappedKey);}
    r.responseJws=body.responseJws;r.state=p.decision==='approve'?'approved':'denied';await s.put('vault_requests',id,r);const eventId=randomUUID();await s.insert('authentication_events',eventId,{id:eventId,requestId:id,windowsDeviceId:r.windowsDeviceId,androidDeviceId:a.id,timestamp:now(),result:enroll?`vault_enrollment_${r.state}`:`vault_phone_${r.state}`,snapshotPath:null});return {state:r.state};
  }));
  app.post('/v1/vault-requests/:id/cancel',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s); const id=(req.params as any).id; requireThat(uuid(id)); const r=await s.get('vault_requests',id);
    requireThat(r&&r.windowsDeviceId===w.id,'not_found',404);const pair=await s.get('device_pairings',r.pairingId);requireThat(pair?.active,'not_paired',403);
    const d=await delegation(r.delegationJws,w,pair);const p=await verified((req.body as any).cancelJws,r.type==='vault-enroll'?w.jwk:d.machineJwk,'vault-cancel');
    fields(p,['requestId','challengeHash']);requireThat(p.purpose==='password-unlock'&&p.requestId===id&&p.challengeHash===hash(r.requestJws),'binding_mismatch');
    requireThat(r.state==='pending','already_processed',409);r.state='cancelled';await s.put('vault_requests',id,r);return {state:'cancelled'};
  }));
}
