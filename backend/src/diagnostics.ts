import type { FastifyInstance,FastifyRequest } from 'fastify';
import type { Store,Row } from './store.js';
import { fields,verified,requireThat,uuid,now } from './protocol.js';
export const diagnosticCodes=['app_started','app_stopped','relay_ready','relay_unavailable','request_sent','push_sent','push_failed','push_missing','approval_verified','approval_denied','approval_expired','approval_failed','camera_started','camera_stopped','camera_failed','remote_received','remote_failed','session_locked','session_unlocked','native_unavailable','native_ready','network_retry','credential_submitted'];
export function validEntry(e:any){
  requireThat(e&&Object.keys(e).sort().join(',')==='code,durationMs,id,level,requestId,timestamp','invalid_diagnostic');
  requireThat(uuid(e.id)&&Number.isSafeInteger(e.timestamp)&&e.timestamp>now()-604800&&e.timestamp<=now()+30&&diagnosticCodes.includes(e.code)&&['info','warning','error'].includes(e.level)&&
    (e.requestId===null||uuid(e.requestId))&&(e.durationMs===null||(Number.isSafeInteger(e.durationMs)&&e.durationMs>=0&&e.durationMs<=300000)),'invalid_diagnostic');
}
export function diagnosticRoutes(app:FastifyInstance,store:Store,device:(r:FastifyRequest,k:'windows'|'android',s?:Store)=>Promise<Row>){
  app.post('/v1/diagnostics',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s);const p=await verified((req.body as any).batchJws,w.jwk,'diagnostic-batch');fields(p,['batchId','windowsDeviceId','issuedAt','expiresAt','entries']);
    requireThat(uuid(p.batchId)&&p.windowsDeviceId===w.id&&Number.isSafeInteger(p.issuedAt)&&Number.isSafeInteger(p.expiresAt)&&p.issuedAt<=now()+30&&p.expiresAt>now()&&p.expiresAt-p.issuedAt<=300&&p.expiresAt>p.issuedAt,'invalid_diagnostic');
    requireThat(Array.isArray(p.entries)&&p.entries.length>0&&p.entries.length<=50,'invalid_diagnostic');p.entries.forEach(validEntry);
    for(const entry of p.entries){const existing=await s.get('diagnostic_logs',entry.id);if(existing){requireThat(existing.windowsDeviceId===w.id,'invalid_diagnostic');continue;}await s.insert('diagnostic_logs',entry.id,{...entry,windowsDeviceId:w.id,receivedAt:now()});}
    await s.pruneLogs(w.id);
    return {recorded:p.entries.length,retentionDays:7};
  }));
  app.get('/v1/diagnostics',async req=>{
    const a=await device(req,'android');const pair=(await store.find('device_pairings','androidDeviceId',a.id)).find(p=>p.active);requireThat(pair,'not_paired',403);
    return {entries:await store.recentLogs(pair.windowsDeviceId,50),retentionDays:7};
  });
  app.get('/v1/device-status',async req=>{
    const w=await device(req,'windows');const pair=(await store.find('device_pairings','windowsDeviceId',w.id)).find(p=>p.active);
    const a=pair?await store.get('android_devices',pair.androidDeviceId):undefined;
    return {paired:!!pair,pushTokenRegistered:!!a?.fcmToken,pushRegisteredAt:a?.pushIssuedAt??null};
  });
}
