import {test} from 'node:test';
import assert from 'node:assert/strict';
import {rootCertificates} from 'node:tls';
import {databaseCa,databaseFailure,databaseOptions} from '../src/config.js';

const certificate=rootCertificates[0]!;

test('provider CA accepts dashboard PEM and escaped newlines',()=>{
  const expected=databaseCa(certificate);
  assert.ok(expected);
  assert.equal(databaseCa(certificate.replace(/\n/g,'\r\n')),expected);
  assert.equal(databaseCa(JSON.stringify(certificate)),expected);
  assert.equal(databaseCa(`'${certificate.replace(/\n/g,'\\n')}'`),expected);
  assert.equal(databaseCa(`${certificate}\n${certificate}`),expected+expected);
});

test('provider CA rejects filenames, private keys and malformed certificates without echoing input',()=>{
  for(const value of ['ca.pem','operator-secret','-----BEGIN PRIVATE KEY-----\noperator-secret\n-----END PRIVATE KEY-----',
    '-----BEGIN CERTIFICATE-----\noperator-secret\n-----END CERTIFICATE-----',certificate+'operator-secret',123]) {
    assert.throws(()=>databaseCa(value),(error: Error)=>{
      assert.match(error.message,/complete PEM CA certificate/);
      assert.doesNotMatch(error.message,/operator-secret/);return true;
    });
  }
  assert.equal(databaseCa('  '),undefined);
});

test('remote database retains CA and verification even with URL SSL overrides',t=>{
  const previous=process.env.DATABASE_CA_PEM;
  process.env.DATABASE_CA_PEM=JSON.stringify(certificate);
  t.after(()=>{if(previous===undefined)delete process.env.DATABASE_CA_PEM;else process.env.DATABASE_CA_PEM=previous;});
  const options=databaseOptions({databaseUrl:'postgres://test:test@db.example.test/db?sslmode=no-verify&sslrootcert=bad&sslcert=bad&sslkey=bad&application_name=phoneunlock'});
  assert.deepEqual(options.ssl,{rejectUnauthorized:true,ca:databaseCa(certificate)});
  const url=new URL(options.connectionString!);
  for(const name of ['sslmode','sslrootcert','sslcert','sslkey'])assert.equal(url.searchParams.has(name),false);
  assert.equal(url.searchParams.get('application_name'),'phoneunlock');
});

test('empty environment CA uses operator config; remote default still verifies TLS',t=>{
  const previous=process.env.DATABASE_CA_PEM;process.env.DATABASE_CA_PEM=' ';
  t.after(()=>{if(previous===undefined)delete process.env.DATABASE_CA_PEM;else process.env.DATABASE_CA_PEM=previous;});
  assert.deepEqual(databaseOptions({databaseUrl:'postgres://test:test@db.example.test/db',databaseCaPem:certificate}).ssl,
    {rejectUnauthorized:true,ca:databaseCa(certificate)});
  assert.deepEqual(databaseOptions({databaseUrl:'postgres://test:test@db.example.test/db'}).ssl,{rejectUnauthorized:true});
  for(const host of ['localhost','127.0.0.1','[::1]'])assert.equal(databaseOptions({databaseUrl:`postgres://test:test@${host}/db`}).ssl,undefined);
});

test('invalid database URL does not disclose credentials',()=>{
  assert.throws(()=>databaseOptions({databaseUrl:'operator-secret'}),/^Error: PostgreSQL configuration invalid$/);
  assert.throws(()=>databaseOptions({databaseUrl:'https://test:operator-secret@db.example.test/db'}),/^Error: PostgreSQL configuration invalid$/);
});

test('database failure distinguishes CA trust errors without disclosing provider messages',()=>{
  for(const code of ['SELF_SIGNED_CERT_IN_CHAIN','DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY']) {
    const error=databaseFailure({code,message:'operator-secret'});
    assert.match(error.message,/DATABASE_CA_PEM/);assert.doesNotMatch(error.message,/operator-secret/);
  }
  assert.match(databaseFailure({code:'ERR_TLS_CERT_ALTNAME_INVALID'}).message,/hostname/);
  assert.match(databaseFailure({code:'28P01'}).message,/28P01/);
  assert.doesNotMatch(databaseFailure({code:'operator-secret',message:'operator-secret'}).message,/operator-secret/);
});
