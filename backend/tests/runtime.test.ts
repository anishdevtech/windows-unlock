import {test} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {once} from 'node:events';
import Fastify from 'fastify';
import {createApp} from '../src/relay.js';
import {MemoryStore} from '../src/store.js';
import {listenForRuntime} from '../src/runtime.js';

test('Vercel server capture does not block startup and captured server serves protected routes',async t=>{
  const app=createApp(new MemoryStore());t.after(()=>app.close());
  const original=http.Server.prototype.listen;let captured:http.Server|undefined;
  let serverFound!:()=>void;
  const captureReady=new Promise<void>(resolve=>{serverFound=resolve;});
  t.mock.method(http.Server.prototype,'listen',function(this:http.Server){
    captured=this;http.Server.prototype.listen=original;serverFound();return this;
  });
  let deadline:ReturnType<typeof setTimeout>|undefined;
  try {
    await Promise.race([Promise.all([listenForRuntime(app,{host:'127.0.0.1',port:0},true),captureReady]),
      new Promise<never>((_,reject)=>{deadline=setTimeout(()=>reject(new Error('Module startup waited for intercepted listen')),1000);})]);
  }finally{if(deadline)clearTimeout(deadline);}
  assert.ok(captured,'Vercel must capture the actual HTTP server');
  assert.equal(captured.listening,false,'The runtime starts the captured server after import');
  // Mirror Vercel's subsequent start, with the real listen restored above.
  captured.listen({host:'127.0.0.1',port:0});await once(captured,'listening');
  const address=captured.address();assert.ok(address&&typeof address!=='string');
  const base=`http://127.0.0.1:${address.port}`;
  const health=await fetch(base+'/health');assert.equal(health.status,200);assert.equal((await health.json() as {status:string}).status,'ok');
  for(const path of ['/v1/authentication-requests/pending','/v1/remote/offer'])assert.equal((await fetch(base+path)).status,401);
});

test('standalone runtime waits for the listener and propagates bind failures',async t=>{
  const app=createApp(new MemoryStore());t.after(()=>app.close());
  await listenForRuntime(app,{host:'127.0.0.1',port:0},false);
  assert.equal(app.server.listening,true);
  const address=app.server.address();assert.ok(address&&typeof address!=='string');
  const conflict=Fastify();t.after(()=>conflict.close());
  await assert.rejects(()=>listenForRuntime(conflict,{host:'127.0.0.1',port:address.port},false),{code:'EADDRINUSE'});
});
