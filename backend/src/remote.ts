import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Store,Row } from './store.js';
import { verified,fields,lifetime,requireThat,uuid,hash,now } from './protocol.js';
type Device=(req:FastifyRequest,kind:'windows'|'android',s?:Store)=>Promise<Row>;
const actions=['lock','sleep','shutdown','restart','camera-start','camera-stop','audio-speaker-start','audio-microphone-start','media-stop'];
const mediaStarts=['camera-start','audio-speaker-start','audio-microphone-start'];
export function remoteRoutes(app:FastifyInstance,store:Store,device:Device) {
  const paired=async(w:string,a:string,id:string,s:Store)=>{
    requireThat(uuid(id));const p=await s.get('device_pairings',id);
    requireThat(p?.active&&p.windowsDeviceId===w&&p.androidDeviceId===a,'not_paired',403);
  };
  app.post('/v1/remote/offers',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s);const jws=(req.body as any).offerJws;
    const p=await verified(jws,w.jwk,'remote-offer');
    fields(p,['offerId','windowsDeviceId','androidDeviceId','pairingId','nonce','issuedAt','expiresAt','actions']);lifetime(p,60);
    requireThat(uuid(p.offerId)&&p.windowsDeviceId===w.id&&Array.isArray(p.actions)&&p.actions.length<=actions.length&&p.actions.every((a:unknown)=>actions.includes(a as string)));
    await paired(w.id,p.androidDeviceId,p.pairingId,s);
    for(const r of await s.find('remote_offers','pairingId',p.pairingId)) if(r.state==='pending'){r.state='superseded';await s.put('remote_offers',r.id,r);}
    await s.insert('remote_offers',p.offerId,{id:p.offerId,...p,offerJws:jws,state:'pending'});
    return {published:true};
  }));
  app.get('/v1/remote/offer',async req=>{
    const a=await device(req,'android');const rows=await store.pending('remote_offers','androidDeviceId',a.id);
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
    if(mediaStarts.includes(p.action)) {
      const k=p.viewerJwk;requireThat(k&&Object.keys(k).sort().join(',')==='e,kty,n'&&k.kty==='RSA'&&k.e==='AQAB'&&typeof k.n==='string'&&/^[A-Za-z0-9_-]+$/.test(k.n));
      const n=Buffer.from(k.n,'base64url');requireThat(n.length===256&&n[0]!>=128&&n.toString('base64url')===k.n,'invalid_viewer_key');
    } else requireThat(p.viewerJwk===null);
    o.state='consumed';await s.put('remote_offers',o.id,o);
    await s.insert('remote_commands',p.commandId,{id:p.commandId,...p,commandJws:jws,expiresAt:o.expiresAt,state:'pending',viewerUntil:now()+(p.action.startsWith('audio-')?600:60)});
    return {commandId:p.commandId,state:'pending'};
  }));
  app.get('/v1/remote/commands/pending',async req=>{
    const w=await device(req,'windows');const rows=await store.pending('remote_commands','windowsDeviceId',w.id);
    const mediaId=(req.query as any)?.mediaId;let mediaStopped=false;
    if(mediaId!==undefined){requireThat(uuid(mediaId));const c=await store.get('remote_commands',mediaId);requireThat(c&&c.windowsDeviceId===w.id,'not_found',404);await paired(w.id,c.androidDeviceId,c.pairingId,store);mediaStopped=c.mediaStopped===true||c.viewerUntil<=now();}
    return {commands:rows.filter(r=>r.state==='pending'&&r.expiresAt>now()).map(r=>({commandJws:r.commandJws,viewerUntil:r.viewerUntil})),mediaStopped};
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
  // Signaling only: media packets go directly between the paired devices.
  app.post('/v1/media/:id',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s);const id=(req.params as any).id;requireThat(uuid(id));const c=await s.get('remote_commands',id);
    requireThat(c&&c.windowsDeviceId===w.id&&mediaStarts.includes(c.action)&&c.viewerUntil>now(),'stream_unavailable',410);await paired(w.id,c.androidDeviceId,c.pairingId,s);
    const b=req.body as any;requireThat(Object.keys(b).sort().join(',')==='descriptorJws,wrappedKey');
    requireThat(typeof b.wrappedKey==='string'&&/^[A-Za-z0-9_-]{342}$/.test(b.wrappedKey)&&Buffer.from(b.wrappedKey,'base64url').length===256&&Buffer.from(b.wrappedKey,'base64url').toString('base64url')===b.wrappedKey);
    const p=await verified(b.descriptorJws,w.jwk,'media-descriptor');fields(p,['mediaId','nonce','commandHash','windowsDeviceId','androidDeviceId','pairingId','action','keyHash','transport','issuedAt','expiresAt']);lifetime(p,c.action==='camera-start'?60:600);
    requireThat(p.mediaId===id&&p.commandHash===hash(c.commandJws)&&p.windowsDeviceId===w.id&&p.androidDeviceId===c.androidDeviceId&&p.pairingId===c.pairingId&&p.action===c.action&&p.expiresAt<=c.viewerUntil&&p.keyHash===hash(b.wrappedKey),'invalid_descriptor');
    const t=p.transport;requireThat(t&&Object.keys(t).sort().join(',')==='addresses,channels,maxFps,packetMs,port,protocol,sampleRate'&&t.protocol==='udp-aesgcm-v1'&&Number.isInteger(t.port)&&t.port>=1024&&t.port<=65535&&t.packetMs===20&&t.maxFps===15);
    requireThat(t.sampleRate===(c.action==='audio-speaker-start'?48000:16000)&&t.channels===(c.action==='audio-speaker-start'?2:1));
    requireThat(Array.isArray(t.addresses)&&t.addresses.length<=8&&t.addresses.every((address:unknown)=>{if(typeof address!=='string'||!/^\d{1,3}(\.\d{1,3}){3}$/.test(address))return false;const n=address.split('.').map(Number);return n.every(v=>v<=255)&&(n[0]===10||(n[0]===172&&n[1]!>=16&&n[1]!<=31)||(n[0]===192&&n[1]===168));}));
    requireThat(!c.descriptorJws||c.descriptorJws===b.descriptorJws,'already_processed',409);c.descriptorJws=b.descriptorJws;c.mediaWrappedKey=b.wrappedKey;await s.put('remote_commands',id,c);return {published:true};
  }));
  app.get('/v1/media/:id',async req=>{
    const a=await device(req,'android');const id=(req.params as any).id;requireThat(uuid(id));const c=await store.get('remote_commands',id);
    requireThat(c&&c.androidDeviceId===a.id,'not_found',404);await paired(c.windowsDeviceId,a.id,c.pairingId,store);requireThat(c.viewerUntil>now()&&!c.mediaStopped,'expired',410);
    return c.descriptorJws&&c.state==='completed'?{descriptorJws:c.descriptorJws,wrappedKey:c.mediaWrappedKey}:{};
  });
  app.post('/v1/media/:id/stop',async req=>store.transaction(async s=>{
    const a=await device(req,'android',s);const id=(req.params as any).id;requireThat(uuid(id));const c=await s.get('remote_commands',id);
    requireThat(c&&c.androidDeviceId===a.id&&mediaStarts.includes(c.action),'not_found',404);await paired(c.windowsDeviceId,a.id,c.pairingId,s);c.mediaStopped=true;await s.put('remote_commands',id,c);return {stopped:true};
  }));
  // Only ciphertext traverses the relay. It retains one latest frame, not a recording.
  app.post('/v1/camera/:id/frame',async req=>store.transaction(async s=>{
    const w=await device(req,'windows',s);const id=(req.params as any).id;requireThat(uuid(id));const c=await s.get('remote_commands',id);
    requireThat(c&&c.windowsDeviceId===w.id&&c.action==='camera-start'&&c.viewerUntil>now()&&!c.mediaStopped,'stream_unavailable',410);await paired(w.id,c.androidDeviceId,c.pairingId,s);
    const b=req.body as any;requireThat(Object.keys(b).sort().join(',')==='ciphertext,envelopeJws,iv,sequence,wrappedKey');
    requireThat(Number.isSafeInteger(b.sequence)&&b.sequence>0&&b.sequence<=600);
    for(const [field,min,max] of [['iv',12,12],['wrappedKey',256,256],['ciphertext',17,45016]] as const) {
      const value=b[field];requireThat(typeof value==='string'&&/^[A-Za-z0-9_-]+$/.test(value));const bytes=Buffer.from(value,'base64url');requireThat(bytes.length>=min&&bytes.length<=max&&bytes.toString('base64url')===value);
    }
    const envelope=await verified(b.envelopeJws,w.jwk,'camera-envelope');
    fields(envelope,['cameraId','commandHash','windowsDeviceId','androidDeviceId','pairingId','keyHash']);
    requireThat(envelope.cameraId===id&&envelope.commandHash===hash(c.commandJws)&&envelope.windowsDeviceId===w.id&&envelope.androidDeviceId===c.androidDeviceId&&envelope.pairingId===c.pairingId&&envelope.keyHash===hash(b.wrappedKey),'invalid_envelope');
    const prev=await s.get('camera_frames',id);requireThat(!prev||prev.envelopeJws===b.envelopeJws,'invalid_envelope');requireThat(!prev||b.sequence>prev.sequence,'replayed_frame',409);
    await s.put('camera_frames',id,{id,...b,windowsDeviceId:w.id,androidDeviceId:c.androidDeviceId,pairingId:c.pairingId,expiresAt:c.viewerUntil});return {stored:true};
  }));
  app.get('/v1/camera/:id/frame',async req=>{
    const a=await device(req,'android');const id=(req.params as any).id;requireThat(uuid(id));const r=await store.get('camera_frames',id);
    if(!r)return {};requireThat(r.androidDeviceId===a.id,'forbidden',403);requireThat(r.expiresAt>now(),'expired',410);await paired(r.windowsDeviceId,a.id,r.pairingId,store);
    const c=await store.get('remote_commands',id);requireThat(c&&!c.mediaStopped,'stream_unavailable',410);
    const after=(req.query as any)?.after;if(after!==undefined){requireThat(typeof after==='string'&&/^[0-9]{1,3}$/.test(after)&&Number(after)<=600);if(r.sequence<=Number(after))return {};}
    return {sequence:r.sequence,iv:r.iv,ciphertext:r.ciphertext,wrappedKey:r.wrappedKey,envelopeJws:r.envelopeJws};
  });
}
