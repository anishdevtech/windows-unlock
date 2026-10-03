import { initializeApp, cert, applicationDefault, getApps } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';
export interface PushSender { send(token:string,requestId:string,expiresAt:number):Promise<void>; }
export function firebasePush():PushSender|undefined {
  if(!process.env.FIREBASE_PROJECT_ID)return undefined;
  const service=process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const app=getApps()[0]??initializeApp({projectId:process.env.FIREBASE_PROJECT_ID,
    credential:service?cert(JSON.parse(service)):applicationDefault()});
  return {async send(token,requestId,expiresAt){
    const ttl=Math.max(0,Math.min(60000,(expiresAt-Math.floor(Date.now()/1000))*1000));
    if(ttl<=0)return;
    let timeout:ReturnType<typeof setTimeout>|undefined;
    try {await Promise.race([getMessaging(app).send({token,data:{kind:'approval',requestId,expiresAt:String(expiresAt)},
      android:{priority:'high',ttl,restrictedPackageName:'dev.windowsunlock.phone'}}),
      new Promise<never>((_resolve,reject)=>{timeout=setTimeout(()=>reject(new Error('push_timeout')),3500);})]);}
    finally{if(timeout)clearTimeout(timeout);}
  }};
}
