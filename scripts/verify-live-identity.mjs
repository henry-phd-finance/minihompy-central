// Real deployment checks. Default: GET-only. --login creates real Auth/central sessions.
// Never save cookies, storageState, request bodies, tokens, screenshots or passwords.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url));
export function validateTargets(c) {
  if(!Array.isArray(c.sites) || c.sites.length<2)throw Error('Two personal sites are required.');
  const urls=[c.centralApiUrl,c.centralPageUrl,...c.sites.map(s=>s.homepage)].map(value=>new URL(value));
  if(urls.some(url=>url.protocol!=='https:' || url.username || url.password || url.search || url.hash))throw Error('Use HTTPS URLs without credentials, query or fragment.');
  if(new Set(c.sites.map(s=>new URL(s.homepage).origin)).size!==c.sites.length)throw Error('Personal sites must use different origins.');
  if(new Set(c.sites.map(s=>s.projectRef)).size!==c.sites.length)throw Error('Personal sites must use different Supabase projects.');
  if(c.sites.some(s=>!s.homepage.endsWith('/') || !/^[a-z]{20}$/.test(s.projectRef) || !/^[0-9a-f-]{36}$/i.test(s.siteId) || !/^[a-z0-9._-]{2,30}$/.test(s.handle) || !/^[A-Z][A-Z0-9_]*$/.test(s.passwordEnv)))throw Error('Invalid public site configuration.');
  return c;
}
const digest=text=>createHash('sha256').update(text).digest('hex');
export async function preflight(c,{fetcher=fetch,clientRoot=resolve(root,'../cyworld')}={}) {
  validateTargets(c);
  const checks=[];
  async function check(name,url,expected) {
    try {
      const r=await fetcher(url,{redirect:'error',signal:AbortSignal.timeout(15000),cache:'no-store'});
      const body=await r.text();
      const passed=r.ok && (!expected || await expected(body));
      checks.push({name,url,status:r.status,passed});return r.ok?body:'';
    }catch{checks.push({name,url,passed:false,error:'network, redirect or response validation failure'});return '';}
  }
  await check('central v2 protocol',c.centralApiUrl+'/health',text=>JSON.parse(text).identity_protocol===2);
  for(const name of ['login.html','login.js','complete.html','complete.js','visit.html','logout.html','visit-flow.js','login-flow.js']) {
    const expected=await readFile(resolve(root,'public',name),'utf8');
    await check('central runtime '+name,new URL(name,c.centralPageUrl.replace(/\/?$/,'/')).href,text=>digest(text)===digest(expected));
  }
  await check('central public configuration',new URL('config.js',c.centralPageUrl.replace(/\/?$/,'/')).href,text=>text.includes(c.centralApiUrl) && text.includes(c.centralPageUrl.replace(/\/$/,'')));
  for(const [i,site] of c.sites.entries()) {
    await check(`site ${i+1} homepage`,site.homepage);
    for(const name of ['login/index.html','visitor-identity.js','visitor-identity-login.js','admin-auth.js','assets/login-flow.js']) {
      const expected=await readFile(resolve(clientRoot,name),'utf8');
      await check(`site ${i+1} runtime ${name}`,new URL(name==='login/index.html'?'login/':name,site.homepage).href,text=>digest(text)===digest(expected));
    }
    await check(`site ${i+1} project mapping`,new URL('supabase-config.js',site.homepage).href,text=>{
      const configured=text.match(/["']?url["']?\s*:\s*["']([^"']+)["']/)?.[1];
      return configured===`https://${site.projectRef}.supabase.co` || configured===`https://${site.projectRef}.supabase.co/`;
    });
    await check(`site ${i+1} central mapping`,new URL('visitor-identity-config.js',site.homepage).href,text=>text.includes(site.siteId) && text.includes(c.centralApiUrl) && text.includes(c.centralPageUrl.replace(/\/$/,'')) && /["']?enabled["']?\s*:\s*true/.test(text));
    await check(`site ${i+1} directory`,`${c.centralApiUrl}/directory?handle=${encodeURIComponent(site.handle)}`,text=>{
      const value=JSON.parse(text); const items=value.items || [];
      return items.some(item=>item.handle===site.handle && item.homepage_url===site.homepage);
    });
  }
  return checks;
}
export async function loginChecks(c,{playwrightPath,chromiumPath=process.env.CHROMIUM_PATH,env=process.env,contextFactory}={}) {
  validateTargets(c);
  const [a,b]=c.sites;
  if((!playwrightPath && !contextFactory) || [a,b].some(site=>!env[site.passwordEnv]))throw Error('Playwright and both password environment variables are required.');
  let browser;
  if(!contextFactory){
    const {chromium}=await import(pathToFileURL(resolve(playwrightPath)));
    browser=await chromium.launch({headless:true,...chromiumPath?{executablePath:chromiumPath}:{}});
  }
  const results=[];let privacyFailure=false, activations=0, pageErrors=0;
  const context=contextFactory?await contextFactory():await browser.newContext({viewport:{width:1280,height:820}});
  const page=await context.newPage();page.setDefaultTimeout(30000);
  const passwords=[a,b].map(site=>env[site.passwordEnv]);
  // Inspect only in memory. Do not retain requests, response bodies or headers.
  page.on('request',request=>{
    const url=request.url(), body=request.postData()||'';
    if(url===c.centralApiUrl+'/activation-tickets')activations++;
    if(passwords.some(p=>url.includes(p) || url.includes(encodeURIComponent(p))))privacyFailure=true;
    if(passwords.some(p=>body.includes(p) || body.includes(JSON.stringify(p)))){
      const personalPasswordDestination=[a,b].some(site=>url===`https://${site.projectRef}.supabase.co/functions/v1/owner-login`);
      if(!personalPasswordDestination)privacyFailure=true;
    }
    if(url.startsWith(c.centralApiUrl) && /"(?:password|refresh_token|email)"\s*:/.test(body))privacyFailure=true;
  });
  page.on('pageerror',()=>{pageErrors++;});
  const assert=(ok,message)=>{if(!ok)throw Error(message);};
  async function state(site,handle,role) {
    await page.waitForFunction(({origin,path,handle,role})=>location.origin===origin && location.pathname===path && window.MinihompySharedIdentity?.state.status===(handle?'identified':'anonymous') && (!handle || window.MinihompySharedIdentity.state.visitor?.handle===handle) && window.MinihompyAdmin?.state.role===role,{origin:new URL(site.homepage).origin,path:new URL(site.homepage).pathname,handle,role});
    assert((await page.locator('[data-menu="settings"]').count()>0)===(role==='admin'),'Administrator UI does not match local role');
    assert(!new URL(page.url()).hash.startsWith('#vt='),'Visit token remained in URL');
  }
  async function visit(site,handle,role) {await page.goto(site.homepage+'?identity_test=1#/board');await state(site,handle,role);assert(new URL(page.url()).hash==='#/board' && new URL(page.url()).search==='?identity_test=1','Original query/menu not restored');}
  async function login(owner,target) {
    await page.locator('#login-auth-toggle').click();
    await page.waitForURL(url=>url.pathname.endsWith('/login.html'));
    assert(await page.locator('input[type=password]').count()===0,'Central ID screen contains a password field');
    await page.locator('#handle').fill(owner.handle);await page.locator('#submit').click();
    await page.waitForURL(url=>url.origin===new URL(owner.homepage).origin && url.pathname===new URL('login/',owner.homepage).pathname);
    await page.waitForFunction(()=>document.querySelector('#password') && !document.querySelector('#password').disabled);
    await page.locator('#password').fill(env[owner.passwordEnv]);await page.locator('#submit').click();await state(target,owner.handle,'reader');
  }
  try {
    await visit(b,null,'reader');await login(a,b);results.push('A login on B; local B role remains reader');
    await page.reload();await state(b,a.handle,'reader');results.push('B reload keeps A and the original route');
    await visit(a,a.handle,'admin');await visit(b,a.handle,'reader');results.push('A to B direct navigation; local administrator remains site-specific');
    for(const third of c.sites.slice(2)){await visit(third,a.handle,'reader');results.push('Additional personal origin recognizes A');}
    await visit(b,a.handle,'reader');await page.locator('#login-auth-toggle').click();await state(b,null,'reader');
    const before=activations;await visit(a,null,'admin');assert(activations===before,'Remaining personal session silently activated central login');
    await page.locator('#login-auth-toggle').click();await state(a,null,'reader');results.push('Visitor logout and own-site local logout; no silent central login');
    await login(b,a);results.push('Account switch: B recognized on A without A admin permission');
    await visit(b,b.handle,'admin');await page.locator('#login-auth-toggle').click();await state(b,null,'reader');
    await page.reload();await state(b,null,'reader');results.push('Own-site combined logout survives reload');
    assert(!privacyFailure,'Credential destination check failed');assert(pageErrors===0,'Browser runtime errors occurred');
    results.push('No password/refresh-token/email sent to central requests');
    return results.map(name=>({name,passed:true}));
  } finally {await context.close();if(browser)await browser.close();}
}
async function main() {
  const args=process.argv.slice(2);let configPath=resolve(root,'scripts/live-targets.json'),out=resolve(root,'docs/verification/login-step5/live-result.json'),playwrightPath,login=false;
  while(args.length){const key=args.shift();if(key==='--config')configPath=args.shift();else if(key==='--output')out=args.shift();else if(key==='--playwright')playwrightPath=args.shift();else if(key==='--login')login=true;else throw Error('Unknown live-check option');}
  const config=validateTargets(JSON.parse(await readFile(configPath,'utf8')));
  const report={checkedAt:new Date().toISOString(),mode:login?'live-login':'read-only-preflight',checks:await preflight(config),login:{status:'not-run'}};
  if(login && report.checks.every(check=>check.passed)) {
    try {report.login={status:'passed',checks:await loginChecks(config,{playwrightPath})};}
    catch {report.login={status:'failed',error:'Login validation failed; no credential-bearing error details retained.'};}
  } else if(login)report.login={status:'blocked',reason:'Deployment preflight failed; no login attempted.'};
  report.passed=report.checks.every(check=>check.passed) && (!login || report.login.status==='passed');
  await mkdir(dirname(resolve(out)),{recursive:true});await writeFile(out,JSON.stringify(report,null,2)+'\n');
  console.log(`${report.checks.filter(c=>c.passed).length}/${report.checks.length} deployment checks passed; login: ${report.login.status}. Report: ${out}`);
  if(!report.passed)process.exitCode=1;
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().catch(()=>{console.error('Live check could not start. Check public configuration and local module paths.');process.exitCode=1;});
