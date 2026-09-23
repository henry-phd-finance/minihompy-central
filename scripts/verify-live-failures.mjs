import {readFile,writeFile} from 'node:fs/promises';import {parseEnv} from 'node:util';import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
import {validateTargets} from './verify-live-identity.mjs';
const args=process.argv.slice(2);let playwright,envFile;
if(args.includes('--help')){console.log('Usage: node scripts/verify-live-failures.mjs --playwright /path/to/playwright/index.mjs [--env-file /private/path/.env]. Real login tests; browser fault injection; waits for ticket expiry.');process.exit(0);}
while(args.length){const flag=args.shift();if(flag==='--playwright')playwright=args.shift();else if(flag==='--env-file')envFile=args.shift();else throw Error('Unknown option');}
if(!playwright)throw Error('--playwright is required');
const {chromium}=await import(pathToFileURL(resolve(playwright)));
const config=validateTargets(JSON.parse(await readFile(new URL('./live-targets.json',import.meta.url),'utf8')));
const env=envFile?parseEnv(await readFile(envFile,'utf8')):process.env;
const password=env[config.sites[0].passwordEnv] || env.pwA;
if(!password)throw Error('The first owner password is required');
const api=config.centralApiUrl;
const [a,b]=config.sites.map(site=>site.homepage);
const results=[];let stage='start',replay,visit,ownerCalls=0,privacyFailure=false;
const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_PATH});
const context=await browser.newContext();const page=await context.newPage();page.setDefaultTimeout(25000);
const note=name=>{results.push({name,passed:true});console.log('PASS: '+name);};
page.on('request',r=>{
 const u=r.url(),body=r.postData()||'';
 if(u===api+'/sessions/complete'&&!replay)replay=JSON.parse(body);
 if(u===api+'/visits/resolve'&&replay&&!visit)visit=JSON.parse(body);
 if(u.endsWith('/functions/v1/owner-login'))ownerCalls++;
 if(u.startsWith(api)&&(/"(?:password|refresh_token|email)"\s*:/.test(body)||body.includes(password)))privacyFailure=true;
});
const state=async(status,role='reader',url=b)=>page.waitForFunction(({status,role,url})=>location.origin+location.pathname===url&&window.MinihompySharedIdentity?.state.status===status&&window.MinihompyAdmin?.state.role===role,{status,role,url});
const post=async(path,body)=>fetch(api+'/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
let passed=false;
try{
 stage='wrong password';await page.goto(b+'#/board');await state('anonymous');stage='central login screen';
 await page.locator('#login-auth-toggle').click();await page.locator('#handle').fill(config.sites[0].handle);await page.locator('#submit').click();
 stage='personal password screen';await page.waitForURL(a+'login/');await page.waitForFunction(()=>!document.querySelector('#password').disabled);
 stage='wrong password response';await page.locator('#password').fill('invalid-test-'+crypto.randomUUID());await page.locator('#submit').click();
 await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('비밀번호를 확인'));
 assert.equal(await page.locator('#password').inputValue(),'');note('Real wrong-password rejection clears the field');
 await page.locator('#password').fill(password);await page.locator('#submit').click();await state('identified');
 stage='activation replay';assert.ok(replay&&visit);const replayResponse=await post('sessions/complete',replay);assert.ok([400,409].includes(replayResponse.status));note('Consumed activation ticket replay rejected by deployed API');
 const exp=JSON.parse(Buffer.from(visit.visit_token.split('.')[1],'base64url')).exp;
 const expiryDeadline=exp*1000+31000;
 stage='personal session reuse';await page.locator('#login-auth-toggle').click();await state('anonymous');const before=ownerCalls;
 await page.locator('#login-auth-toggle').click();await page.locator('#handle').fill(config.sites[0].handle);await page.locator('#submit').click();await state('identified');assert.equal(ownerCalls,before);note('Explicit login reuses A personal session without another password request');
 stage='blocked central storage';await context.addInitScript(({origin,basePath})=>{
  if(location.origin!==origin||!location.pathname.startsWith(basePath))return;
  window.blockLogout=true;const remove=Storage.prototype.removeItem;
  Storage.prototype.removeItem=function(key){if(window.blockLogout&&key==='minihompy.identity.session.v1')throw Error('test storage block');return remove.call(this,key);};
 },{origin:new URL(config.centralPageUrl).origin,basePath:new URL(config.centralPageUrl).pathname});
 await page.locator('#login-auth-toggle').click();await page.waitForURL(url=>url.pathname.endsWith('/logout.html'));await page.locator('#retry').waitFor({state:'visible'});
 assert.match(await page.locator('#message').textContent(),/저장소/);assert.ok(await page.evaluate(()=>!!localStorage.getItem('minihompy.identity.session.v1')));
 await page.evaluate(()=>{window.blockLogout=false;});await page.locator('#retry').click();await state('anonymous');note('Injected storage block cannot report logout success; retry succeeds');
 stage='network interruption';await context.route('**/identity-api/health',r=>r.abort('failed'));
 await page.goto(b+'?fault_test=1#/board');await page.waitForFunction(()=>window.MinihompySharedIdentity?.state.status==='error');
 assert.equal(new URL(page.url()).hash,'#/board');await context.unroute('**/identity-api/health');await page.locator('#visitor-identity-retry').click();await state('anonymous');note('Injected central network failure preserves menu and recovers via retry');
 // Clear the remaining personal session without the central storage fault.
 await page.goto(a+'#/board');await state('anonymous','admin',a);await page.evaluate(()=>location.assign(window.MinihompySharedIdentity.getLogoutUrl()));
 await page.waitForURL(url=>url.pathname.endsWith('/logout.html'));await page.locator('#retry').waitFor({state:'visible'});await page.evaluate(()=>{window.blockLogout=false;});await page.locator('#retry').click();await state('anonymous','admin',a);
 const clientResult=await page.evaluate(async()=>{const r=await window.MinihompyBackend.getClient('admin').auth.signOut({scope:'local'});return !r.error;});assert.ok(clientResult);
 stage='expired visit ticket';const wait=Math.max(0,expiryDeadline-Date.now());console.log('Waiting for actual visit-ticket expiry ('+Math.ceil(wait/1000)+' seconds).');await new Promise(done=>setTimeout(done,wait));
 const expired=await post('visits/resolve',visit);assert.ok([400,401].includes(expired.status));note('Naturally expired visit ticket rejected by deployed API');
 assert.ok(!privacyFailure);note('No password, refresh token or email in central request bodies');passed=true;
}catch(error){console.log('FAIL: '+stage+' ('+error.name+'); sensitive details omitted');
 results.push({name:stage,passed:false,errorType:error.name});}
finally{await context.close();await browser.close();await writeFile(new URL('../docs/verification/login-step5/live-failures.json',import.meta.url),JSON.stringify({checkedAt:new Date().toISOString(),mode:'real-auth-and-api-with-browser-fault-injection',passed,checks:results},null,2)+'\n');}
if(!passed)process.exitCode=1;
