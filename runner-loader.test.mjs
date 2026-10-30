import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readdir,rm,readFile,stat,unlink} from 'node:fs/promises';
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

function mediaResponse(bytes,changes={}){
  const media={byte_size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),extension:'pdf',...changes};
  return new Response(bytes,{headers:{'Content-Type':'application/octet-stream','X-Task-Media':encodeURIComponent(JSON.stringify(media))}});
}

test('streamed media uses a private local file, exact hash and size, and only one outstanding file',async()=>{
  const f=fixture('export async function runTask(){}'),parent=await mkdtemp(path.join(tmpdir(),'loader-test-'));
  const original=f.fetcher,bytes=Buffer.from('synthetic media bytes');let streams=0,mediaDirectory;
  f.fetcher=async(url,options)=>{if(JSON.parse(options.body).op==='bundle')return original(url,options);streams++;return mediaResponse(bytes);};
  const importer=async()=>({async runTask(_task,options){
    mediaDirectory=options.mediaDirectory;assert.equal(path.isAbsolute(mediaDirectory),true);assert.equal(path.basename(mediaDirectory),'media');
    if(process.platform!=='win32')assert.equal((await stat(mediaDirectory)).mode&0o777,0o700);
    const first=await options.call('media_stream',{index:0});
    assert.equal(path.dirname(first.file_path),mediaDirectory);assert.match(path.basename(first.file_path),/^[a-f0-9-]{36}\.pdf$/);
    if(process.platform!=='win32')assert.equal((await stat(first.file_path)).mode&0o777,0o600);
    assert.deepEqual(await readFile(first.file_path),bytes);assert.equal(first.media.byte_size,bytes.length);assert.equal('base64' in first,false);
    await assert.rejects(options.call('media_stream',{index:1}),error=>error.code==='HOSTED_MEDIA_BUSY');assert.equal(streams,1);
    await unlink(first.file_path);const second=await options.call('media_stream',{index:1});
    assert.notEqual(second.file_path,first.file_path);assert.equal((await readdir(mediaDirectory)).length,1);await unlink(second.file_path);
    return {status:'idle'};
  }});
  try{assert.equal((await loadAndRun(task,{...f,parent,importer})).status,'idle');assert.equal(streams,2);assert.deepEqual(await readdir(parent),[]);}
  finally{await rm(parent,{recursive:true,force:true});}
});

test('a second in-flight media stream is refused before another POST',async()=>{
  const f=fixture('export async function runTask(){}'),original=f.fetcher;let release,posts=0;
  f.fetcher=async(url,options)=>{if(JSON.parse(options.body).op==='bundle')return original(url,options);posts++;return new Promise(resolve=>release=()=>resolve(mediaResponse(Buffer.from('fixture'))));};
  const importer=async()=>({async runTask(_task,{call}){
    const pending=call('media_stream',{index:0});await assert.rejects(call('media_stream',{index:1}),error=>error.code==='HOSTED_MEDIA_BUSY');
    release();await pending;return {status:'idle'};
  }});
  await loadAndRun(task,{...f,importer});assert.equal(posts,1);
});

test('media metadata, length and hash mismatches fail closed and remove every temporary file',async()=>{
  const bytes=Buffer.from('synthetic media');
  for(const [changes,code] of [[{byte_size:10485761},'HOSTED_MEDIA_INVALID'],[{extension:'../escape'},'HOSTED_MEDIA_INVALID'],
    [{byte_size:bytes.length+1},'HOSTED_MEDIA_SIZE_MISMATCH'],[{byte_size:bytes.length-1},'HOSTED_MEDIA_SIZE_MISMATCH'],
    [{sha256:'0'.repeat(64)},'HOSTED_MEDIA_HASH_MISMATCH']]){
    const f=fixture('export async function runTask(){}'),parent=await mkdtemp(path.join(tmpdir(),'loader-test-')),original=f.fetcher;
    f.fetcher=async(url,options)=>JSON.parse(options.body).op==='bundle'?original(url,options):mediaResponse(bytes,changes);
    const importer=async()=>({runTask:(_task,{call})=>call('media_stream',{index:0})});
    try{await assert.rejects(loadAndRun(task,{...f,parent,importer}),error=>error.code===code);assert.deepEqual(await readdir(parent),[]);}
    finally{await rm(parent,{recursive:true,force:true});}
  }
});

test('a stalled stream is cancelled within its deadline with no POST replay or file residue',async()=>{
  const f=fixture('export async function runTask(){}'),parent=await mkdtemp(path.join(tmpdir(),'loader-test-')),original=f.fetcher;let posts=0,cancelled=0;
  f.fetcher=async(url,options)=>{
    if(JSON.parse(options.body).op==='bundle')return original(url,options);posts++;
    return new Response(new ReadableStream({pull(){return new Promise(()=>{});},cancel(){cancelled++;}}),{headers:{'Content-Type':'application/octet-stream',
      'X-Task-Media':encodeURIComponent(JSON.stringify({byte_size:1,sha256:'0'.repeat(64),extension:'pdf'}))}});
  };
  try{
    const importer=async()=>({runTask:(_task,{call})=>call('media_stream',{index:0})});
    await assert.rejects(loadAndRun(task,{...f,parent,importer,mediaTimeout:20}),error=>error.code==='HOSTED_MEDIA_TIMEOUT');
    assert.equal(posts,1);assert.equal(cancelled,1);assert.deepEqual(await readdir(parent),[]);
  }finally{await rm(parent,{recursive:true,force:true});}
});

test('stream indices and privileged fields are rejected before any media POST',async()=>{
  for(const fields of [{index:-1},{index:2},{index:'0'},{index:0,run_id:task.run_id},{index:0,extra:true}]){
    const f=fixture('export async function runTask(){}'),importer=async()=>({runTask:(_task,{call})=>call('media_stream',fields)});
    await assert.rejects(loadAndRun(task,{...f,importer}),error=>error.code==='HOSTED_ACTION_REFUSED');assert.equal(f.requests.length,1);
  }
});

test('two maximum-size media streams complete sequentially under a 48 MiB V8 heap',context=>{
  const loader=pathToFileURL(fileURLToPath(new URL('./runner-loader.mjs',import.meta.url))).href;
  const script=`
    import {createHash} from 'node:crypto';import {unlink} from 'node:fs/promises';import {loadAndRun} from ${JSON.stringify(loader)};
    const source='export async function runTask(){}',chunk=new Uint8Array(65536).fill(97),size=10485760,hash=createHash('sha256');
    for(let i=0;i<size/chunk.length;i++)hash.update(chunk);const metadata={byte_size:size,sha256:hash.digest('hex'),extension:'pdf'};
    const env={CF_ORIGIN:'https://relay.example',HOSTED_RUNNER_KEY:'F'.repeat(43),HOSTED_BUNDLE_SHA256:createHash('sha256').update(source).digest('hex')};let streams=0;
    const fetcher=async(_url,options)=>{if(JSON.parse(options.body).op==='bundle')return new Response(source);streams++;let remaining=size;
      return new Response(new ReadableStream({pull(controller){if(!remaining){controller.close();return;}remaining-=chunk.length;controller.enqueue(chunk);}}),
        {headers:{'Content-Type':'application/octet-stream','X-Task-Media':encodeURIComponent(JSON.stringify(metadata))}});};
    const importer=async()=>({async runTask(_task,{call}){for(let index=0;index<2;index++){const file=await call('media_stream',{index});await unlink(file.file_path);}return {status:'idle'};}});
    await loadAndRun(${JSON.stringify(task)},{env,fetcher,importer});console.log(JSON.stringify({streams,max_rss_kib:process.resourceUsage().maxRSS}));
  `;
  const result=spawnSync(process.execPath,['--max-old-space-size=48','--input-type=module','--eval',script],{encoding:'utf8',timeout:20000});
  assert.ifError(result.error);assert.equal(result.status,0,result.stderr);const metadata=JSON.parse(result.stdout);
  assert.equal(metadata.streams,2);assert.ok(metadata.max_rss_kib<160*1024,'The loader alone must leave substantial space inside the shared 512 MiB budget');
  context.diagnostic(JSON.stringify(metadata));
});

test('the generic report loader forwards a cancellation capability and keeps its terminal result',async()=>{
  const source='export async function runTask(task,{call}){await call("report_cancel",{proof:{synthetic:true},closed:true});return {status:"report_canceled"};}',f=fixture(source),parent=await mkdtemp(path.join(tmpdir(),'loader-cancel-test-'));
  try{
    assert.deepEqual(await loadAndRun({...task,mode:'report'},{...f,parent}),{status:'report_canceled'});
    assert.deepEqual(f.requests[1].body,{op:'report_cancel',proof:{synthetic:true},closed:true,run_id:task.run_id,lease_token:task.lease_token});
    assert.deepEqual(await readdir(parent),[]);
  }finally{await rm(parent,{recursive:true,force:true});}
});
