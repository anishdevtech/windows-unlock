import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Fastify from 'fastify';
import {configureApp,serverOptions} from '../src/relay.js';
import {MemoryStore} from '../src/store.js';

test('Vercel entry point satisfies the Fastify builder detection contract',()=>{
  // Upstream detector: vercel/vercel packages/fastify/src/build.ts.
  // This is the deployment failure reported by Vercel, not a transitive import check.
  const source=readFileSync(new URL('../src/server.ts',import.meta.url),'utf8');
  const detector=/(?:from|require|import)\s*(?:\(\s*)?["']fastify["']\s*(?:\))?/g;
  assert.match(source,detector,'The recognized server entry point must directly import Fastify');
  const config=JSON.parse(readFileSync(new URL('../vercel.json',import.meta.url),'utf8'));
  assert.equal(config.framework,'fastify');
  assert.equal(config.outputDirectory,undefined,'Do not point the server entry-point detector at a static output directory');
});

test('entry-point construction registers the protected relay routes',async t=>{
  const app=Fastify(serverOptions());configureApp(app,new MemoryStore());
  t.after(()=>app.close());
  const health=await app.inject({method:'GET',url:'/health'});
  assert.equal(health.statusCode,200);assert.equal(health.json().status,'ok');
  assert.equal(health.headers['cache-control'],'no-store');
  const root=await app.inject({method:'GET',url:'/'});
  assert.equal(root.statusCode,302);assert.equal(root.headers.location,'/health');
  assert.equal(root.headers['cache-control'],'no-store');
  for(const url of ['/v1/authentication-requests/pending','/v1/remote/offer']) {
    const result=await app.inject({method:'GET',url});assert.equal(result.statusCode,401);
  }
});
