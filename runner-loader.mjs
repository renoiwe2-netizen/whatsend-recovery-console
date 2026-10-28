// Public generic loader. Business code is downloaded privately and hash pinned.
import {createHash,timingSafeEqual} from 'node:crypto';
import {mkdtemp,writeFile,rm,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';

const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const OPS=new Set(['session_get','preview','claim','payload','media','checkpoint','complete','fail','session_put','report_claim','report_binding','report_settle','report_finish','finish']);
const safeFailure=code=>Object.assign(new Error(code),{code});
function taskValue(value){
  if(!value||Object.keys(value).some(key=>!['run_id','lease_token','mode'].includes(key))||!UUID.test(value.run_id||'')||!UUID.test(value.lease_token||'')||!['send','report'].includes(value.mode))throw safeFailure('INVALID_HOSTED_TASK');
  return {run_id:value.run_id,lease_token:value.lease_token,mode:value.mode};
}
async function limitedBody(response,limit){
  if(!response.body)throw safeFailure('HOSTED_RELAY_REFUSED');
  const reader=response.body.getReader(),parts=[];let length=0;
  while(true){const part=await reader.read();if(part.done)break;length+=part.value.length;if(length>limit){await reader.cancel();throw safeFailure('HOSTED_RELAY_TOO_LARGE');}parts.push(part.value);}
  const text=Buffer.concat(parts).toString('utf8');
  if(!response.ok){
    let code;try{const value=JSON.parse(text);code=value?.code||value?.error;}catch{}
    throw safeFailure(/^[A-Z][A-Z0-9_]{0,99}$/.test(code||'')?code:'HOSTED_RELAY_REFUSED');
  }
  return text;
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
export async function loadAndRun(input,{env=process.env,fetcher=fetch,puppeteer=null,parent=tmpdir(),importer=url=>import(url)}={}){
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
  const bundleResponse=await post('bundle',{},false),raw=await limitedBody(bundleResponse,2*1024*1024);
  let source=raw;if((bundleResponse.headers.get('Content-Type')||'').includes('application/json')){
    let payload;try{payload=JSON.parse(raw);}catch{throw safeFailure('HOSTED_BUNDLE_INVALID');}source=payload?.source;
  }
  if(typeof source!=='string'||!source.length||Buffer.byteLength(source)>1024*1024)throw safeFailure('HOSTED_BUNDLE_INVALID');
  const digest=createHash('sha256').update(source).digest();
  if(!timingSafeEqual(digest,Buffer.from(env.HOSTED_BUNDLE_SHA256,'hex')))throw safeFailure('HOSTED_BUNDLE_HASH_MISMATCH');
  const directory=await mkdtemp(path.join(parent,'private-task-'+task.run_id+'-'));let started=false,browser;
  try{
    const modulePath=path.join(directory,'runtime.mjs');await writeFile(modulePath,source,{mode:0o600});
    const runtime=await importer(pathToFileURL(modulePath).href);
    if(typeof runtime.runTask!=='function')throw safeFailure('HOSTED_BUNDLE_INVALID');
    const call=async(op,fields={})=>{
      if(!OPS.has(op)||!fields||Array.isArray(fields)||typeof fields!=='object'||Object.keys(fields).some(key=>['op','run_id','lease_token'].includes(key)))throw safeFailure('HOSTED_ACTION_REFUSED');
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
    return await runtime.runTask(task,{call,launch});
  }finally{await closeManagedBrowser(browser);await rm(directory,{recursive:true,force:true});}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    let raw='';for await(const part of process.stdin){raw+=part;if(raw.length>2048)throw safeFailure('INVALID_HOSTED_TASK');}
    const result=await loadAndRun(JSON.parse(raw)),safe={status:['submitted','idle','report_pending','report_applied','report_settlement_uncertain','failed'].includes(result?.status)?result.status:'failed'};
    if(typeof result?.code==='string'&&/^[A-Z0-9_]{1,100}$/.test(result.code))safe.code=result.code;
    process.stdout.write(JSON.stringify(safe)+'\n');if(safe.status==='failed')process.exitCode=1;
  }catch(error){process.stdout.write(JSON.stringify({status:'failed',code:/^[A-Z0-9_]{1,100}$/.test(error?.code||'')?error.code:'HOSTED_LOADER_FAILED'})+'\n');process.exitCode=1;}
}
