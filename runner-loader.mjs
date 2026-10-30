// Public generic loader. Business code is downloaded privately and hash pinned.
import {createHash,timingSafeEqual,randomUUID} from 'node:crypto';
import {mkdtemp,writeFile,rm,mkdir,chmod,open,lstat,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const OPS=new Set(['session_get','preview','claim','payload','media','media_stream','checkpoint','complete','fail','session_put','report_claim','report_binding','report_settle','report_cancel','report_finish','reconcile_binding','reconcile_complete','finish']);
const safeFailure=code=>Object.assign(new Error(code),{code});
async function within(promise,milliseconds,code){
  let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(safeFailure(code)),milliseconds);})]);}
  finally{clearTimeout(timer);}
}
function taskValue(value){
  if(!value||Object.keys(value).some(key=>!['run_id','lease_token','mode'].includes(key))||!UUID.test(value.run_id||'')||!UUID.test(value.lease_token||'')||!['send','report','import_reconcile'].includes(value.mode))throw safeFailure('INVALID_HOSTED_TASK');
  return {run_id:value.run_id,lease_token:value.lease_token,mode:value.mode};
}
async function limitedBody(response,limit){
  if(!response.body)throw safeFailure('HOSTED_RELAY_REFUSED');
  const declared=Number(response.headers.get('Content-Length'));
  if(Number.isFinite(declared)&&declared>limit){await response.body.cancel();throw safeFailure('HOSTED_RELAY_TOO_LARGE');}
  const reader=response.body.getReader(),decoder=new TextDecoder('utf-8',{fatal:true});let length=0,text='',done=false;
  try{
    while(true){const part=await reader.read();if(part.done){done=true;break;}length+=part.value.length;if(length>limit)throw safeFailure('HOSTED_RELAY_TOO_LARGE');text+=decoder.decode(part.value,{stream:true});}
    text+=decoder.decode();
  }finally{if(!done)try{await reader.cancel();}catch{}reader.releaseLock();}
  if(!response.ok){
    let code;try{const value=JSON.parse(text);code=value?.code||value?.error;}catch{}
    throw safeFailure(/^[A-Z][A-Z0-9_]{0,99}$/.test(code||'')?code:'HOSTED_RELAY_REFUSED');
  }
  return text;
}
async function streamedFile(response,directory,{timeout=20000}={}){
  if(!response.ok){await limitedBody(response,16384);throw safeFailure('HOSTED_RELAY_REFUSED');}
  let media;
  try{
    const header=response.headers.get('X-Task-Media');
    if(!header||header.length>16384)throw new Error();
    media=JSON.parse(decodeURIComponent(header));
    if(!media||typeof media!=='object'||Array.isArray(media)||!Number.isSafeInteger(media.byte_size)||media.byte_size<1||media.byte_size>10485760||
      !/^[a-f0-9]{64}$/.test(media.sha256||'')||!/^[a-z0-9]{1,8}$/.test(media.extension||'')||
      (response.headers.get('Content-Type')||'').split(';')[0].trim().toLowerCase()!=='application/octet-stream'||!response.body)throw new Error();
    const declared=response.headers.get('Content-Length');
    if(declared!==null&&(!/^[0-9]+$/.test(declared)||Number(declared)!==media.byte_size))throw new Error();
  }catch{try{await within(response.body?.cancel(),1000,'HOSTED_MEDIA_TIMEOUT');}catch{}throw safeFailure('HOSTED_MEDIA_INVALID');}
  const filePath=path.join(directory,randomUUID()+'.'+media.extension),hash=createHash('sha256');
  let file,reader,length=0,complete=false;const deadline=Date.now()+timeout;
  try{
    file=await open(filePath,'wx',0o600);reader=response.body.getReader();
    while(true){
      const part=await within(reader.read(),Math.max(1,deadline-Date.now()),'HOSTED_MEDIA_TIMEOUT');
      if(part.done)break;length+=part.value.byteLength;
      if(length>media.byte_size)throw safeFailure('HOSTED_MEDIA_SIZE_MISMATCH');
      hash.update(part.value);await within(file.writeFile(part.value),Math.max(1,deadline-Date.now()),'HOSTED_MEDIA_TIMEOUT');
    }
    if(length!==media.byte_size)throw safeFailure('HOSTED_MEDIA_SIZE_MISMATCH');
    if(hash.digest('hex')!==media.sha256)throw safeFailure('HOSTED_MEDIA_HASH_MISMATCH');
    complete=true;return {media,file_path:filePath};
  }finally{
    if(reader){try{await within(reader.cancel(),1000,'HOSTED_MEDIA_TIMEOUT');}catch{}try{reader.releaseLock();}catch{}}
    if(file)await file.close();
    if(!complete)try{await unlink(filePath);}catch(error){if(error.code!=='ENOENT')throw safeFailure('HOSTED_MEDIA_CLEANUP_UNCERTAIN');}
  }
}
async function closeManagedBrowser(browser){
  if(!browser)return;
  const child=browser.process?.();if(child&&(child.exitCode!==null||child.signalCode))return;
  let timer;
  try{await Promise.race([Promise.resolve().then(()=>browser.close()),new Promise((_,reject)=>{timer=setTimeout(()=>reject(safeFailure('HOSTED_CLOSE_TIMEOUT')),10000);})]);}
  catch{
    if(child)try{if(process.platform==='win32'||!child.pid)child.kill('SIGKILL');else process.kill(-child.pid,'SIGKILL');}catch{try{child.kill('SIGKILL');}catch{}}
  }finally{clearTimeout(timer);}
}
export async function loadAndRun(input,{env=process.env,fetcher=fetch,puppeteer=null,parent=tmpdir(),importer=url=>import(url),mediaTimeout=20000}={}){
  const task=taskValue(input);let origin;
  try{origin=new URL(env.CF_ORIGIN);}catch{throw safeFailure('HOSTED_CONFIGURATION_REQUIRED');}
  if(origin.protocol!=='https:'||origin.pathname!=='/'||origin.username||origin.password||origin.search||origin.hash||origin.port||
    !/^[A-Za-z0-9_-]{32,128}$/.test(env.HOSTED_RUNNER_KEY||'')||!/^[a-f0-9]{64}$/.test(env.HOSTED_BUNDLE_SHA256||''))throw safeFailure('HOSTED_CONFIGURATION_REQUIRED');
  const endpoint=new URL('/internal/hosted',origin).href;
  const post=async(op,fields={},withLease=true)=>{
    const response=await fetcher(endpoint,{method:'POST',headers:{Authorization:'Bearer '+env.HOSTED_RUNNER_KEY,'Content-Type':'application/json'},
      body:JSON.stringify({...fields,op,...(withLease?{run_id:task.run_id,lease_token:task.lease_token}:{})}),redirect:'error',signal:AbortSignal.timeout(op==='report_settle'?45000:20000)});
    return response;
  };
  let bundleResponse=await post('bundle',{},false),raw=await limitedBody(bundleResponse,2*1024*1024);
  let source=raw;if((bundleResponse.headers.get('Content-Type')||'').includes('application/json')){
    let payload;try{payload=JSON.parse(raw);}catch{throw safeFailure('HOSTED_BUNDLE_INVALID');}source=payload?.source;
  }
  if(typeof source!=='string'||!source.length||Buffer.byteLength(source)>1024*1024)throw safeFailure('HOSTED_BUNDLE_INVALID');
  const digest=createHash('sha256').update(source).digest();
  if(!timingSafeEqual(digest,Buffer.from(env.HOSTED_BUNDLE_SHA256,'hex')))throw safeFailure('HOSTED_BUNDLE_HASH_MISMATCH');
  const directory=await mkdtemp(path.join(parent,'private-task-'+task.run_id+'-'));let started=false,browser;
  try{
    await chmod(directory,0o700);
    const modulePath=path.join(directory,'runtime.mjs');await writeFile(modulePath,source,{mode:0o600});
    // Do not retain the downloaded JSON/string while Chromium is running.
    source=null;raw=null;bundleResponse=null;
    const mediaDirectory=path.join(directory,'media');await mkdir(mediaDirectory,{mode:0o700});
    const runtime=await importer(pathToFileURL(modulePath).href);let activeMedia=null,mediaLoading=false;
    if(typeof runtime.runTask!=='function')throw safeFailure('HOSTED_BUNDLE_INVALID');
    const call=async(op,fields={})=>{
      if(!OPS.has(op)||!fields||Array.isArray(fields)||typeof fields!=='object'||Object.keys(fields).some(key=>['op','run_id','lease_token'].includes(key)))throw safeFailure('HOSTED_ACTION_REFUSED');
      if(op==='media_stream'){
        if(Object.keys(fields).length!==1||!Number.isInteger(fields.index)||fields.index<0||fields.index>1)throw safeFailure('HOSTED_ACTION_REFUSED');
        if(mediaLoading)throw safeFailure('HOSTED_MEDIA_BUSY');
        mediaLoading=true;
        try{
          if(activeMedia){try{await lstat(activeMedia);throw safeFailure('HOSTED_MEDIA_BUSY');}catch(error){if(error.code!=='ENOENT')throw error;}activeMedia=null;}
          const descriptor=await streamedFile(await post(op,fields),mediaDirectory,{timeout:mediaTimeout});
          activeMedia=descriptor.file_path;return descriptor;
        }finally{mediaLoading=false;}
      }
      const raw=await limitedBody(await post(op,fields),16*1024*1024);
      try{return JSON.parse(raw);}catch{throw safeFailure('HOSTED_RELAY_INVALID');}
    };
    const launch=async()=>{
      if(started)throw safeFailure('HOSTED_BROWSER_ALREADY_STARTED');started=true;
      const library=puppeteer||(await import('puppeteer-core')).default,profile=path.join(directory,'profile');await mkdir(profile,{mode:0o700});
      const chromeEnv={};for(const key of ['PATH','HOME','LANG'])if(env[key])chromeEnv[key]=env[key];
      browser=await library.launch({executablePath:'/usr/bin/chromium',headless:true,userDataDir:profile,env:chromeEnv,timeout:25000,
        args:['--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--disable-extensions','--disable-gpu','--disable-dev-shm-usage','--renderer-process-limit=2']});
      return browser;
    };
    return await runtime.runTask(task,{call,launch,mediaDirectory});
  }finally{await closeManagedBrowser(browser);await within(rm(directory,{recursive:true,force:true,maxRetries:2,retryDelay:100}),5000,'HOSTED_CLEANUP_UNCERTAIN');}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    let raw='';for await(const part of process.stdin){raw+=part;if(raw.length>2048)throw safeFailure('INVALID_HOSTED_TASK');}
    const result=await loadAndRun(JSON.parse(raw)),safe={status:['submitted','idle','report_pending','report_applied','report_canceled','report_settlement_uncertain','import_reconciled','failed'].includes(result?.status)?result.status:'failed'};
    if(typeof result?.code==='string'&&/^[A-Z0-9_]{1,100}$/.test(result.code))safe.code=result.code;
    process.stdout.write(JSON.stringify(safe)+'\n');if(safe.status==='failed')process.exitCode=1;
  }catch(error){process.stdout.write(JSON.stringify({status:'failed',code:/^[A-Z0-9_]{1,100}$/.test(error?.code||'')?error.code:'HOSTED_LOADER_FAILED'})+'\n');process.exitCode=1;}
}
