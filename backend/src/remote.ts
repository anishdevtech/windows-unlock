import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Store,Row } from './store.js';
import { verified,fields,lifetime,requireThat,uuid,hash,now } from './protocol.js';
type Device=(req:FastifyRequest,kind:'windows'|'android',s?:Store)=>Promise<Row>;
const actions=['lock','sleep','shutdown','restart','camera-start','camera-stop'];
export function remoteRoutes(app:FastifyInstance,store:Store,device:Device) {
  const paired=async(w:string,a:string,id:string,s:Store)=>{
    requireThat(uuid(id));const p=await s.get('device_pairings',id);
    requireThat(p?.active&&p.windowsDeviceId===w&&p.androidDeviceId===a,'not_paired',403);
  };
  app.post('/v1/remote/offers',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s);const jws=(req.body as any).offerJws;
    const p=await verified(jws,w.jwk,'remote-offer');
    fields(p,['offerId','windowsDeviceId','androidDeviceId','pairingId','nonce','issuedAt','expiresAt','actions']);lifetime(p,60);
    requireThat(uuid(p.offerId)&&p.windowsDeviceId===w.id&&Array.isArray(p.actions)&&p.actions.length<=6&&p.actions.every((a:unknown)=>actions.includes(a as string)));
    await paired(w.id,p.androidDeviceId,p.pairingId,s);
    for(const r of await s.find('remote_offers','pairingId',p.pairingId)) if(r.state==='pending'){r.state='superseded';await s.put('remote_offers',r.id,r);}
    await s.insert('remote_offers',p.offerId,{id:p.offerId,...p,offerJws:jws,state:'pending'});
    return {published:true};
  }));
  app.get('/v1/remote/offer',async req=>{
    const a=await device(req,'android');const rows=await store.find('remote_offers','androidDeviceId',a.id);
    const r=rows.find(r=>r.state==='pending'&&r.expiresAt>now());
    if(!r)return {};
    await paired(r.windowsDeviceId,a.id,r.pairingId,store);return {offerJws:r.offerJws};
  });
  app.post('/v1/remote/commands',async req=>store.transaction(async s=>{
    const a=await device(req,'android',s);const jws=(req.body as any).commandJws;
    const p=await verified(jws,a.approvalJwk,'remote-command');
    fields(p,['commandId','offerId','windowsDeviceId','androidDeviceId','pairingId','offerHash','action','viewerJwk']);
    requireThat(uuid(p.commandId)&&uuid(p.offerId));await paired(p.windowsDeviceId,a.id,p.pairingId,s);const o=await s.get('remote_offers',p.offerId);
    requireThat(o&&o.state==='pending','already_processed',409);requireThat(o.expiresAt>now(),'expired',410);
    requireThat(p.androidDeviceId===a.id&&p.windowsDeviceId===o.windowsDeviceId&&p.androidDeviceId===o.androidDeviceId&&p.pairingId===o.pairingId&&p.offerHash===hash(o.offerJws),'binding_mismatch');
    await paired(o.windowsDeviceId,a.id,o.pairingId,s);requireThat(o.actions.includes(p.action),'disabled',403);
    if(p.action==='camera-start') {
      const k=p.viewerJwk;requireThat(k&&Object.keys(k).sort().join(',')==='e,kty,n'&&k.kty==='RSA'&&k.e==='AQAB'&&typeof k.n==='string'&&/^[A-Za-z0-9_-]+$/.test(k.n));
      const n=Buffer.from(k.n,'base64url');requireThat(n.length===256&&n[0]!>=128&&n.toString('base64url')===k.n,'invalid_viewer_key');
    } else requireThat(p.viewerJwk===null);
    o.state='consumed';await s.put('remote_offers',o.id,o);
    await s.insert('remote_commands',p.commandId,{id:p.commandId,...p,commandJws:jws,expiresAt:o.expiresAt,state:'pending',viewerUntil:now()+60});
    return {commandId:p.commandId,state:'pending'};
  }));
  app.get('/v1/remote/commands/pending',async req=>{
    const w=await device(req,'windows');const rows=await store.find('remote_commands','windowsDeviceId',w.id);
    return {commands:rows.filter(r=>r.state==='pending'&&r.expiresAt>now()).map(r=>({commandJws:r.commandJws}))};
  });
  app.get('/v1/remote/commands/:id',async req=>{
    const a=await device(req,'android');const id=(req.params as any).id;requireThat(uuid(id));const r=await store.get('remote_commands',id);
    requireThat(r&&r.androidDeviceId===a.id,'not_found',404);await paired(r.windowsDeviceId,a.id,r.pairingId,store);
    return {state:r.state,resultJws:r.resultJws??null};
  });
  app.post('/v1/remote/commands/:id/result',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s);const jws=(req.body as any).resultJws;const p=await verified(jws,w.jwk,'remote-result');
    fields(p,['commandId','commandHash','result','timestamp']);const id=(req.params as any).id;requireThat(uuid(id)&&p.commandId===id);
    const r=await s.get('remote_commands',id);requireThat(r&&r.windowsDeviceId===w.id&&r.state==='pending','already_processed',409);
    requireThat(p.commandHash===hash(r.commandJws)&&['accepted','failed','disabled'].includes(p.result)&&Number.isSafeInteger(p.timestamp));
    r.state='completed';r.resultJws=jws;await s.put('remote_commands',id,r);return {recorded:true};
  }));
  // Only ciphertext traverses the relay. It retains one latest frame, not a recording.
  app.post('/v1/camera/:id/frame',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s);const id=(req.params as any).id;requireThat(uuid(id));const c=await s.get('remote_commands',id);
    requireThat(c&&c.windowsDeviceId===w.id&&c.action==='camera-start'&&c.viewerUntil>now(),'stream_unavailable',410);await paired(w.id,c.androidDeviceId,c.pairingId,s);
    const b=req.body as any;requireThat(Object.keys(b).sort().join(',')==='ciphertext,iv,sequence,wrappedKey');
    requireThat(Number.isSafeInteger(b.sequence)&&b.sequence>0&&b.sequence<=120);
    for(const [field,min,max] of [['iv',12,12],['wrappedKey',256,256],['ciphertext',17,45016]] as const) {
      const value=b[field];requireThat(typeof value==='string'&&/^[A-Za-z0-9_-]+$/.test(value));const bytes=Buffer.from(value,'base64url');requireThat(bytes.length>=min&&bytes.length<=max&&bytes.toString('base64url')===value);
    }
    const prev=await s.get('camera_frames',id);requireThat(!prev||b.sequence>prev.sequence,'replayed_frame',409);
    await s.put('camera_frames',id,{id,...b,windowsDeviceId:w.id,androidDeviceId:c.androidDeviceId,pairingId:c.pairingId,expiresAt:c.viewerUntil});return {stored:true};
  }));
  app.get('/v1/camera/:id/frame',async req=>{
    const a=await device(req,'android');const id=(req.params as any).id;requireThat(uuid(id));const r=await store.get('camera_frames',id);
    if(!r)return {};requireThat(r.androidDeviceId===a.id,'forbidden',403);requireThat(r.expiresAt>now(),'expired',410);await paired(r.windowsDeviceId,a.id,r.pairingId,store);
    return {sequence:r.sequence,iv:r.iv,ciphertext:r.ciphertext,wrappedKey:r.wrappedKey};
  });
}
