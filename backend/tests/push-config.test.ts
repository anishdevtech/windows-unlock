import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {deleteApp,getApps} from 'firebase-admin/app';
import {firebasePush} from '../src/push.js';
import {createApp} from '../src/relay.js';
import {MemoryStore} from '../src/store.js';

test('malformed Firebase credentials do not crash the protected relay or disclose secrets',async t=>{
  const invalid=[
    '{operator-secret',JSON.stringify({project_info:{project_id:'push-test'},client:[]}),
    'null','[]',JSON.stringify({type:'service_account',project_id:123,private_key:'operator-secret',client_email:'operator-secret'}),
    JSON.stringify({type:'service_account',project_id:'push-test',client_email:'test@example.test',private_key:'operator-secret'})
  ];
  for(const value of invalid) {
    const warnings:string[]=[];
    const push=firebasePush({VERCEL:'1',FIREBASE_PROJECT_ID:'push-test',FIREBASE_SERVICE_ACCOUNT_JSON:value},message=>warnings.push(message));
    assert.equal(push,undefined);assert.equal(warnings.length,1);
    assert.match(warnings[0]!,/push disabled/);assert.doesNotMatch(warnings[0]!,/operator-secret/);
    const app=createApp(new MemoryStore(),undefined,push);t.after(()=>app.close());
    assert.equal((await app.inject({method:'GET',url:'/health'})).statusCode,200);
    assert.equal((await app.inject({method:'GET',url:'/v1/authentication-requests/pending'})).statusCode,401);
  }
});

test('missing Vercel service account and mismatched Firebase projects disable push clearly',()=>{
  for(const env of [
    {VERCEL:'1',FIREBASE_PROJECT_ID:'push-test'},
    {FIREBASE_SERVICE_ACCOUNT_JSON:'operator-secret'},
    {FIREBASE_PROJECT_ID:'push-test',FIREBASE_SERVICE_ACCOUNT_JSON:JSON.stringify({type:'service_account',project_id:'other-project',client_email:'test@example.test',private_key:'operator-secret'})}
  ]) {
    const warnings:string[]=[];
    assert.equal(firebasePush(env,message=>warnings.push(message)),undefined);
    assert.equal(warnings.length,1);assert.doesNotMatch(warnings[0]!,/operator-secret/);
  }
  const warnings:string[]=[];assert.equal(firebasePush({},message=>warnings.push(message)),undefined);assert.deepEqual(warnings,[]);
});

test('valid service-account configuration initializes isolated push sender without network access',async t=>{
  const key=generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({type:'pkcs8',format:'pem'});
  const env={VERCEL:'1',FIREBASE_PROJECT_ID:'push-config-test',FIREBASE_SERVICE_ACCOUNT_JSON:JSON.stringify({
    type:'service_account',project_id:'push-config-test',client_email:'push-test@push-config-test.iam.gserviceaccount.com',private_key:key
  })};
  const warnings:string[]=[];
  const push=firebasePush(env,message=>warnings.push(message));assert.ok(push);
  t.after(async()=>{for(const app of getApps())if(app.name==='windows-unlock-push-push-config-test')await deleteApp(app);});
  assert.ok(firebasePush(env,message=>warnings.push(message)),'Repeated initialization reuses the same project app');
  assert.deepEqual(warnings,[]);
  // Expired hints must never contact FCM. No live service account/token is used.
  await push.send('not-a-real-token','not-a-real-request',Math.floor(Date.now()/1000)-1);
});
