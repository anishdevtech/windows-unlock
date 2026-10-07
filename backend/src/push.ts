import { initializeApp, cert, applicationDefault, getApps } from 'firebase-admin/app';
import { getMessaging,type Message } from 'firebase-admin/messaging';
export function approvalPushPayload(token:string,requestId:string,expiresAt:number):Message {
  const ttl=Math.max(0,Math.min(60000,(expiresAt-Math.floor(Date.now()/1000))*1000));
  return {token,notification:{title:'Windows login request',body:'Tap to review your laptop request and authenticate securely.'},
    data:{kind:'approval',requestId,approvalRequestId:requestId,expiresAt:String(expiresAt)},
    android:{priority:'high',ttl,restrictedPackageName:'dev.windowsunlock.phone',notification:{channelId:'approval_requests_v1',icon:'ic_notification',tag:requestId,visibility:'private',defaultSound:true}}};
}
export interface PushSender { send(token:string,requestId:string,expiresAt:number):Promise<void>; }
export function firebasePush(env:NodeJS.ProcessEnv=process.env,report:(message:string)=>void=message=>console.warn(message)):PushSender|undefined {
  const projectId=env.FIREBASE_PROJECT_ID?.trim();
  const service=env.FIREBASE_SERVICE_ACCOUNT_JSON?.trim();
  const disabled=(reason:string)=>{report(`WINDOWS-UNLOCK push disabled: ${reason} Approval polling remains available.`);return undefined;};
  if(!projectId) {
    if(service)return disabled('Set FIREBASE_PROJECT_ID to the service account project_id.');
    return undefined;
  }
  // Push is an optional delivery hint. Broken credentials must not stop the relay.
  let credential;
  if(service) {
    let account;
    try {account=JSON.parse(service);}catch{return disabled('FIREBASE_SERVICE_ACCOUNT_JSON is invalid JSON; use the complete Firebase Admin service-account JSON.');}
    if(!account || typeof account!=='object' || Array.isArray(account) || account.type!=='service_account' ||
      !['project_id','client_email','private_key'].every(key=>typeof account[key]==='string'&&account[key].trim().length>0)) {
      return disabled('FIREBASE_SERVICE_ACCOUNT_JSON must be a service_account with project_id, client_email and private_key. Android google-services.json is not a server credential.');
    }
    if(account.project_id!==projectId)return disabled('FIREBASE_PROJECT_ID must match the service account project_id.');
    try {credential=cert(account);}catch{return disabled('The Firebase Admin service-account key is invalid; download a valid key from Firebase Project settings > Service accounts.');}
  } else {
    // Vercel has no Google application-default identity unless explicitly configured.
    if(env.VERCEL==='1')return disabled('FIREBASE_SERVICE_ACCOUNT_JSON is missing; configure the Firebase Admin service-account JSON on Vercel.');
    try {credential=applicationDefault();}catch{return disabled('Google application-default credentials could not be initialized.');}
  }
  let app;
  try {
    const name=`windows-unlock-push-${projectId}`;
    app=getApps().find(value=>value.name===name)??initializeApp({projectId,credential},name);
  }catch{return disabled('Firebase Admin could not be initialized; check protected Firebase configuration.');}
  return {async send(token,requestId,expiresAt){
    const ttl=Math.max(0,Math.min(60000,(expiresAt-Math.floor(Date.now()/1000))*1000));
    if(ttl<=0)return;
    let timeout:ReturnType<typeof setTimeout>|undefined;
    try {await Promise.race([getMessaging(app).send(approvalPushPayload(token,requestId,expiresAt)),
      new Promise<never>((_resolve,reject)=>{timeout=setTimeout(()=>reject(new Error('push_timeout')),3500);})]);}
    finally{if(timeout)clearTimeout(timeout);}
  }};
}
