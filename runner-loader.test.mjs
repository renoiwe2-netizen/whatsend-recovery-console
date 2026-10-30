import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {loadAndRun} from './runner-loader.mjs';
const task={run_id:'11111111-1111-4111-8111-111111111111',lease_token:'22222222-2222-4222-8222-222222222222',mode:'send'};
const key='F'.repeat(43),origin='https://relay.example';
function fixture(source){
  const requests=[],env={CF_ORIGIN:origin,HOSTED_RUNNER_KEY:key,HOSTED_BUNDLE_SHA256:createHash('sha256').update(source).digest('hex'),PATH:'synthetic-path',HOME:'synthetic-home',LANG:'C.UTF-8',SECRET_VALUE:'must-stay-server-side'};
  const fetcher=async(url,options)=>{requests.push({url,options,body:JSON.parse(options.body)});return JSON.parse(options.body).op==='bundle'?new Response(source,{headers:{'Content-Type':'text/javascript'}}):Response.json({ok:true});};
  return {env,requests,fetcher};
}
test('a private pinned bundle is loaded and every operation carries only its fixed lease',async()=>{
  const source='export async function runTask(task,{call}){await call("preview");return {status:"submitted"};}',f=fixture(source),parent=await mkdtemp(path.join(tmpdir(),'loader-test-'));
  try{
    assert.deepEqual(await loadAndRun(task,{...f,parent}),{status:'submitted'});assert.equal(f.requests.length,2);
    assert.deepEqual(f.requests[0].body,{op:'bundle'});assert.deepEqual(f.requests[1].body,{op:'preview',run_id:task.run_id,lease_token:task.lease_token});
    assert.ok(f.requests.every(r=>r.url===origin+'/internal/hosted'&&r.options.headers.Authorization==='Bearer '+key&&r.options.redirect==='error'));
    assert.deepEqual(await readdir(parent),[]);
  }finally{await rm(parent,{recursive:true,force:true});}
});
test('a hash mismatch cannot import or execute downloaded code',async()=>{
  const f=fixture('export const wrong=true;');f.env.HOSTED_BUNDLE_SHA256='0'.repeat(64);let imports=0;
  await assert.rejects(loadAndRun(task,{...f,importer:async()=>{imports++;}}),e=>e.code==='HOSTED_BUNDLE_HASH_MISMATCH');assert.equal(imports,0);
});

test('the reconcile mode allows only named operations carrying the assigned lease',async()=>{
  const source='export async function runTask(task,{call}){if(task.mode!=="import_reconcile")throw new Error("wrong mode");await call("reconcile_binding");await call("reconcile_complete",{verified:true});return {status:"import_reconciled"};}',f=fixture(source),parent=await mkdtemp(path.join(tmpdir(),'loader-test-'));
  try{
    assert.deepEqual(await loadAndRun({...task,mode:'import_reconcile'},{...f,parent}),{status:'import_reconciled'});
    assert.deepEqual(f.requests.map(request=>request.body),[
      {op:'bundle'},
      {op:'reconcile_binding',run_id:task.run_id,lease_token:task.lease_token},
      {verified:true,op:'reconcile_complete',run_id:task.run_id,lease_token:task.lease_token},
    ]);
    assert.ok(f.requests.every(request=>request.options.redirect==='error'));
    assert.deepEqual(await readdir(parent),[]);
  }finally{await rm(parent,{recursive:true,force:true});}
});

test('invalid mode values cannot fetch or execute a private bundle',async()=>{
  for(const mode of ['import','IMPORT_RECONCILE','',null,undefined,[],{},1]){
    const f=fixture('export async function runTask(){return {status:"import_reconciled"};}');let imports=0;
    await assert.rejects(loadAndRun({...task,mode},{...f,importer:async()=>{imports++;}}),e=>e.code==='INVALID_HOSTED_TASK');
    assert.equal(f.requests.length,0);assert.equal(imports,0);
  }
});

test('the executable publishes only the safe reconcile result without private fields',()=>{
  const source='export async function runTask(){return {status:"import_reconciled",code:"IMPORT_RECONCILED",contacts:["private-value"]};}',f=fixture(source);
  const loader=fileURLToPath(new URL('./runner-loader.mjs',import.meta.url));
  const script=`globalThis.fetch=async()=>new Response(${JSON.stringify(source)},{headers:{'Content-Type':'text/javascript'}});process.argv[1]=${JSON.stringify(loader)};await import(${JSON.stringify(pathToFileURL(loader).href)});`;
  const result=spawnSync(process.execPath,['--input-type=module','--eval',script],{input:JSON.stringify({...task,mode:'import_reconcile'}),encoding:'utf8',env:{...process.env,...f.env},timeout:10000});
  assert.ifError(result.error);assert.equal(result.status,0,result.stderr);
  assert.deepEqual(JSON.parse(result.stdout),{status:'import_reconciled',code:'IMPORT_RECONCILED'});
});
test('the generic launcher preserves sandbox and strips server secrets from the Chromium environment',async()=>{
  const source='export async function runTask(task,{launch}){const browser=await launch();await browser.close();return {status:"submitted"};}',f=fixture(source);let options;
  const puppeteer={async launch(value){options=value;return {async close(){}};}};
  assert.equal((await loadAndRun(task,{...f,puppeteer})).status,'submitted');assert.equal(options.headless,true);assert.equal(options.executablePath,'/usr/bin/chromium');
  assert.deepEqual(options.env,{PATH:'synthetic-path',HOME:'synthetic-home',LANG:'C.UTF-8'});assert.equal(options.args.some(a=>/no-sandbox|disable-web-security/.test(a)),false);assert.equal(options.timeout,25000);
});
test('business code cannot request an arbitrary RPC or replace its assigned run identifiers',async()=>{
  for(const operation of ['await call("rpc",{name:"anything"})','await call("preview",{run_id:"different"})','await call("reconcile_sql")','await call("reconcile_binding",{lease_token:"different"})','await call("reconcile_complete",{op:"preview"})','await call("reconcile_complete",[])']){
    const source='export async function runTask(task,{call}){'+operation+';return {status:"submitted"};}',f=fixture(source);
    await assert.rejects(loadAndRun(task,f),e=>e.code==='HOSTED_ACTION_REFUSED');assert.equal(f.requests.length,1);
  }
});
test('the relay exposes only structured safe error codes to private business code',async()=>{
  const source='export async function runTask(task,{call}){await call("session_get");}',f=fixture(source),original=f.fetcher;
  f.fetcher=async(url,options)=>JSON.parse(options.body).op==='bundle'?original(url,options):Response.json({error:'SESSION_EXPIRED'},{status:403});
  await assert.rejects(loadAndRun(task,f),e=>e.code==='SESSION_EXPIRED');
});
