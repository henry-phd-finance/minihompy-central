import assert from 'node:assert/strict';
import { loginChecks } from './verify-live-identity.mjs';
import { readFile, mkdir } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createIdentityDb } from './helpers/identity-db.mjs';
import { handleIdentityApiRequest } from '../supabase/functions/identity-api/handler.js';
const clientRoot = resolve(process.env.MINIHOMPY_CLIENT_ROOT || fileURLToPath(new URL('../../cyworld/', import.meta.url)));
const { handleOwnerLogin } = await import(pathToFileURL(resolve(clientRoot, 'supabase/functions/owner-login/handler.js')));
const { initialSettings, initialProfile } = await import(pathToFileURL(resolve(clientRoot, 'scripts/settings-fixture.mjs')));
const { chromium } = await import(pathToFileURL(resolve(process.argv[2])));
const { pg, db } = await createIdentityDb();
const central = 'https://central.github.io/hub', centralApi = 'https://cccccccccccccccccccc.supabase.co/functions/v1/identity-api';
const ownerA = '11111111-1111-4111-8111-111111111111', ownerB = '22222222-2222-4222-8222-222222222222';
const alice = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', member: 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa', handle: 'alice', owner: ownerA, ref: 'aaaaaaaaaaaaaaaaaaaa' };
const bob = { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', member: 'bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb', handle: 'bob', owner: ownerB, ref: 'bbbbbbbbbbbbbbbbbbbb' };
const carol = { id:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',member:'dddddddd-1111-4111-8111-dddddddddddd',handle:'carol',owner:'33333333-3333-4333-8333-333333333333',ref:'dddddddddddddddddddd' };
for (const site of [alice, bob, carol]) {
  await pg.query('insert into private.identity_members(id,handle,display_name) values($1,$2,$2)', [site.member, site.handle]);
  await pg.query("insert into private.identity_sites(id,member_id,origin,base_path,homepage_url,login_url,supabase_project_ref,supabase_publishable_key,verification_status) values($1,$2,$3,'/minihompy/',$4,$5,$6,'sb_publishable_browserfixture','verified')", [site.id, site.member, `https://${site.handle}.github.io`, `https://${site.handle}.github.io/minihompy/`, `https://${site.handle}.github.io/minihompy/login/`, site.ref]);
  await pg.query('insert into private.identity_bindings(site_id,member_id,local_user_id) values($1,$2,$3)', [site.id,site.member,site.owner]);
}
const tokenFor = site => ['eyJhbGciOiJIUzI1NiJ9', Buffer.from(JSON.stringify({ sub: site.owner, role: 'authenticated', aud: 'authenticated', iss: `https://${site.ref}.supabase.co/auth/v1`, exp: Math.floor(Date.now()/1000)+3600, iat: Math.floor(Date.now()/1000), is_anonymous: false })).toString('base64url'), 'dGVzdC1zaWduYXR1cmU'].join('.');
const tokens = new Map([alice,bob,carol].map(site => [site.ref,tokenFor(site)]));
const requests = [], outbound = [];
function user(site) { return { id: site.owner, email: 'private-owner@example.test', role: 'authenticated', is_anonymous: false, aud: 'authenticated', app_metadata: {}, user_metadata: {}, identities: [] }; }
async function authFetch(url, init) {
  outbound.push({ url, body: init.body });
  const site = [alice,bob,carol].find(s => new URL(url).hostname === `${s.ref}.supabase.co`); assert.ok(site, 'Only registered personal Auth may be contacted');
  if (url.includes('/auth/v1/token')) {
    const body = JSON.parse(init.body);
    if (body.password !== 'browser-password') return Response.json({ error: 'bad-password' }, { status: 400 });
    assert.equal(body.email, 'private-owner@example.test');
    return Response.json({ access_token: tokens.get(site.ref), refresh_token: `refresh-${site.handle}`, token_type:'bearer', expires_in:3600, user:user(site) });
  }
  const good = init.headers.Authorization === `Bearer ${tokens.get(site.ref)}`;
  if (!good) return Response.json({ error:'unauthorized' }, { status:401 });
  return Response.json(url.endsWith('/auth/v1/user') ? user(site) : true);
}
const options = { supabaseClient:db, centralSecret:'browser-test-only-central-signing-secret-1234', allowedOrigins:new Set(['https://central.github.io','https://alice.github.io','https://bob.github.io','https://carol.github.io']), fetcher:authFetch };
const browser = await chromium.launch({ headless:true, executablePath: process.env.CHROMIUM_PATH });
const contexts = [];
const out = resolve(clientRoot, 'docs/verification/login-step2'); await mkdir(out,{recursive:true});
const mime = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.png':'image/png', '.jpg':'image/jpeg', '.svg':'image/svg+xml', '.woff2':'font/woff2' };
async function contextFor({ width=1280, blockedSession=false, blockedLocal=false, standalone=false }={}) {
  const context = await browser.newContext({viewport:{width,height:820}}); contexts.push(context);
  if (blockedSession || blockedLocal) await context.addInitScript(({blockedSession,blockedLocal}) => {
    const original = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key,value) {
      if (location.origin === 'https://central.github.io' && ((blockedSession && this === sessionStorage) || (blockedLocal && this === localStorage))) throw new DOMException('blocked','SecurityError');
      return original.call(this,key,value);
    };
  },{blockedSession,blockedLocal});
  const errors=[]; const page=await context.newPage(); page.setDefaultTimeout(10000); page.on('pageerror',e=>errors.push(e.message));
  await context.route('**/*',async route=>{
    const request=route.request(), url=new URL(request.url());
    requests.push({url:url.href,method:request.method(),body:request.postData(),headers:request.headers()});
    const headers={'access-control-allow-origin':request.headers().origin || '*','access-control-allow-headers':'*','access-control-allow-methods':'GET, POST, OPTIONS','cache-control':'no-store'};
    const respond=async response=>route.fulfill({status:response.status,headers:{...headers,...Object.fromEntries(response.headers)},body:await response.text()});
    if (request.method()==='OPTIONS') return route.fulfill({status:204,headers});
    if (url.href.startsWith(centralApi)) return respond(await handleIdentityApiRequest(new Request(url.href,{method:request.method(),headers:request.headers(),...(request.method()!=='GET'?{body:request.postData()}: {})}),options));
    const site=[alice,bob,carol].find(s=>url.hostname===`${s.ref}.supabase.co`);
    if (site) {
      if(url.pathname.endsWith('/functions/v1/owner-login')) return respond(await handleOwnerLogin(new Request(url.href,{method:request.method(),headers:request.headers(),body:request.postData()}),{
        config:{MINIHOMPY_SITE_ORIGIN:`https://${site.handle}.github.io`, MINIHOMPY_OWNER_EMAIL:'private-owner@example.test',MINIHOMPY_OWNER_ID:site.owner,SUPABASE_URL:`https://${site.ref}.supabase.co`,MINIHOMPY_PUBLIC_KEY:'sb_publishable_browserfixture'},fetcher:authFetch}));
      if(url.pathname.startsWith('/auth/') || url.pathname.endsWith('/rpc/is_minihompy_admin')) return respond(await authFetch(url.href,{headers:{Authorization:request.headers().authorization},body:request.postData()}));
      let data=[];
      if(url.pathname.endsWith('/minihompy_settings')) data=[{payload:initialSettings,revision:1}];
      if(url.pathname.endsWith('/minihompy_profile')) data=[initialProfile];
      return route.fulfill({json:data,headers});
    }
    let root, path;
    if(url.origin==='https://central.github.io' && url.pathname.startsWith('/hub/')) {
      if(url.pathname==='/hub/config.js') return route.fulfill({contentType:'text/javascript',body:`window.MINIHOMPY_CENTRAL_CONFIG=${JSON.stringify({apiBaseUrl:centralApi,pageBaseUrl:central})};`});
      root=resolve(fileURLToPath(new URL('../public/',import.meta.url)));path=url.pathname.slice('/hub/'.length);}
    else {
      const home=[alice,bob,carol].find(s=>url.origin===`https://${s.handle}.github.io`);
      if(!home || !url.pathname.startsWith('/minihompy/')) return route.fulfill({status:404,body:'Unexpected test URL'});
      root=clientRoot;path=url.pathname.slice('/minihompy/'.length);
      if(path==='supabase-config.js') return route.fulfill({contentType:'text/javascript',body:`window.MINIHOMPY_SUPABASE={url:'https://${home.ref}.supabase.co',publishableKey:'sb_publishable_browserfixture'};`});
      if(path==='visitor-identity-config.js') return route.fulfill({contentType:'text/javascript',body:`window.MINIHOMPY_VISITOR_IDENTITY_CONFIG=${JSON.stringify({enabled:!standalone,siteId:home.id,handle:home.handle,centralApiUrl:centralApi,centralPageUrl:central,healthTimeoutMs:1500})};`});
    }
    if(!path || path.endsWith('/'))path+='index.html';
    const filename=resolve(root,path);
    if(!filename.startsWith(root+'/'))return route.fulfill({status:403,body:'Forbidden'});
    try {return route.fulfill({contentType:mime[extname(filename)]||'application/octet-stream',body:await readFile(filename)});}
    catch{return route.fulfill({status:404,body:'Missing fixture asset'});}
  });
  return {page,context,errors};
}
async function start(page, auto=false) {
  await page.goto(`https://bob.github.io/minihompy/${auto ? '?admin=login' : ''}#/board`);
  if(auto) {await page.waitForURL('**/hub/login.html?**');return;}
  await page.waitForFunction(()=>window.MinihompySharedIdentity?.state.status==='anonymous' && window.MinihompySettings?.status==='ready');
  await page.locator('#login-auth-toggle').click(); await page.waitForURL('**/hub/login.html?**');
}
async function chooseAlice(page) {
  await page.locator('#handle').fill('alice'); await page.locator('#submit').click();
  await page.waitForURL('https://alice.github.io/minihompy/login/');
}
async function identified(page) {
  await page.waitForURL('https://bob.github.io/minihompy/#/board');
  await page.waitForFunction(()=>window.MinihompySharedIdentity?.state.visitor?.handle==='alice');
  assert.equal(await page.locator('#visitor-name').textContent(),'alice');
  assert.equal(await page.evaluate(()=>window.MinihompyAdmin.state.role),'reader');
  assert.equal(await page.locator('[data-menu="settings"]').count(),0);
  assert.equal(await page.locator('[data-view-slot="main"]').getAttribute('data-view'),'board');
}
try {
  assert.equal(await readFile(resolve(clientRoot,'assets/login.css'),'utf8'),await readFile(new URL('../public/login.css',import.meta.url),'utf8'));
  assert.equal(await readFile(resolve(clientRoot,'assets/login-flow.js'),'utf8'),await readFile(new URL('../public/login-flow.js',import.meta.url),'utf8'));
  for(const width of [1280,375]) {
    const {page,errors}=await contextFor({width});await start(page);
    assert.equal(await page.locator('input[type=password]').count(),0);
    await page.locator('#handle').fill('missing');await page.locator('#submit').click();await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('찾을 수'));
    await page.locator('#handle').fill('alice');
    const handlePosition = await page.locator('#handle').boundingBox();
    await page.screenshot({path:resolve(out,`central-${width}.png`)});
    await chooseAlice(page);await page.locator('#password').waitFor({state:'visible'});await page.waitForFunction(()=>!document.querySelector('#password').disabled);
    assert.equal(await page.locator('#handle').inputValue(),'alice');assert.equal(await page.locator('input[type=email]').count(),0);
    const personalPosition = await page.locator('#handle').boundingBox();
    assert.ok(Math.abs(handlePosition.y-personalPosition.y)<2, 'ID field should stay in the same position between origins');
    await page.screenshot({path:resolve(out,`personal-${width}.png`)});
    await page.locator('#password').fill('wrong');await page.locator('#submit').click();await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('비밀번호를 확인'));
    assert.equal(await page.locator('#password').inputValue(),'');
    const countBefore=requests.filter(r=>r.url.endsWith('/activation-tickets')).length;
    await page.locator('#password').fill('browser-password');await page.locator('#submit').click();await identified(page);
    assert.equal(requests.filter(r=>r.url.endsWith('/activation-tickets')).length,countBefore+1);
    await page.screenshot({path:resolve(out,`returned-${width}.png`)});
    // Explicitly start a new central login; A's personal session should be reused.
    const passwordCalls=requests.filter(r=>r.url.endsWith('/owner-login')).length;
    await page.evaluate(()=>window.MinihompyAdmin.openLogin());
    await page.waitForURL('**/hub/login.html?**');
    await page.locator('#handle').fill('alice');await page.locator('#submit').click();await identified(page);
    assert.equal(requests.filter(r=>r.url.endsWith('/owner-login')).length,passwordCalls);
    assert.deepEqual(errors,[]);await page.close();
    console.log(`PASS: ${width}px ID → personal password → central exchange → B board; wrong ID/password, session reuse and role separation.`);
  }
  {
    const {page,errors}=await contextFor();await start(page);await chooseAlice(page);await page.waitForFunction(()=>!document.querySelector('#password').disabled);
    await page.locator('#cancel').click();await page.waitForURL('https://bob.github.io/minihompy/#/board');
    await page.waitForFunction(()=>window.MinihompySharedIdentity?.state.status==='anonymous');assert.deepEqual(errors,[]);await page.close();
    console.log('PASS: cancellation clears central verifier and returns to the original B menu.');
  }
  {
    const {page}=await contextFor();await start(page);await chooseAlice(page);await page.waitForFunction(()=>!document.querySelector('#password').disabled);
    await pg.query("update private.identity_login_attempts set intent_expires_at=now()-interval '1 second' where activated_at is null");
    await page.locator('#password').fill('browser-password');await page.locator('#submit').click();await page.locator('#restart').waitFor({state:'visible'});
    assert.match(await page.locator('#message').textContent(),/만료/);await page.close();console.log('PASS: expired login offers a new flow instead of repeating a consumed intent.');
  }
  {
    const {page}=await contextFor({blockedSession:true});await page.goto(`${central}/login.html?site_id=${bob.id}`);
    const before=requests.filter(r=>r.url.endsWith('/login-intents')).length;
    await page.locator('#handle').fill('alice');await page.locator('#submit').click();await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('저장소'));
    assert.equal(requests.filter(r=>r.url.endsWith('/login-intents')).length,before);await page.close();console.log('PASS: blocked tab storage fails before issuing an intent.');
  }
  {
    const {page}=await contextFor({blockedLocal:true});await start(page);await chooseAlice(page);await page.waitForFunction(()=>!document.querySelector('#password').disabled);
    const before=requests.filter(r=>r.url.endsWith('/sessions/complete')).length;
    await page.locator('#password').fill('browser-password');await page.locator('#submit').click();await page.waitForURL('**/hub/complete.html');
    await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('저장소'));
    assert.equal(requests.filter(r=>r.url.endsWith('/sessions/complete')).length,before);await page.close();console.log('PASS: blocked central persistent storage does not consume the activation ticket.');
  }
  {
    const {page}=await contextFor();const before=requests.filter(r=>r.url.endsWith('/sessions/complete')).length;
    await page.goto(`${central}/complete.html#ticket=foreign&attempt_id=foreign`);await page.waitForFunction(()=>document.querySelector('#message').textContent.includes('이 탭'));
    assert.equal(new URL(page.url()).hash,'');assert.equal(requests.filter(r=>r.url.endsWith('/sessions/complete')).length,before);await page.close();console.log('PASS: unrelated tab cannot complete a login and ticket is removed from the URL.');
  }
  {
    const {page,errors}=await contextFor({standalone:true});await page.goto('https://alice.github.io/minihompy/');await page.waitForFunction(()=>window.MinihompySettings?.status==='ready');
    const before=requests.filter(r=>r.url.startsWith(centralApi)).length;
    await page.locator('#login-auth-toggle').click();await page.locator('#login-email').fill('private-owner@example.test');await page.locator('#login-password').fill('browser-password');await page.locator('#login-submit').click();
    await page.waitForFunction(()=>window.MinihompyAdmin?.state.role==='admin');assert.equal(requests.filter(r=>r.url.startsWith(centralApi)).length,before);assert.deepEqual(errors,[]);await page.close();console.log('PASS: standalone admin email/password login remains local.');
  }
  {
    await pg.query('update private.identity_sites set login_url=$1 where id=$2', ['https://alice.github.io/minihompy/?login_intent=',alice.id]);
    const {page,errors}=await contextFor();await start(page,true);await chooseAlice(page);await page.waitForFunction(()=>!document.querySelector('#password').disabled);
    await page.locator('#password').fill('browser-password');await page.locator('#submit').click();await identified(page);assert.deepEqual(errors,[]);await page.close();
    console.log('PASS: legacy homepage login_url reaches the new password page without losing the base path.');
  }
  {
    const {page,errors}=await contextFor(); await start(page); await chooseAlice(page);
    await page.waitForFunction(()=>!document.querySelector('#password').disabled);
    await page.locator('#password').fill('browser-password'); await page.locator('#submit').click(); await identified(page);
    await page.reload(); await identified(page);
    await page.goto('https://carol.github.io/minihompy/?keep=yes#/board');
    await page.waitForFunction(()=>window.MinihompySharedIdentity?.state.visitor?.handle==='alice');
    assert.equal(new URL(page.url()).search,'?keep=yes'); assert.equal(new URL(page.url()).hash,'#/board');
    assert.equal(await page.evaluate(()=>window.MinihompyAdmin.state.role),'reader');
    assert.equal(await page.locator('[data-menu="settings"]').count(),0);
    await page.locator('#login-auth-toggle').click();
    await page.waitForFunction(()=>location.hostname==='carol.github.io' && window.MinihompySharedIdentity?.state.status==='anonymous');
    assert.equal(await page.locator('#login-auth-toggle').textContent(),'로그인');
    const activations = requests.filter(r=>r.url.endsWith('/activation-tickets')).length;
    await page.goto('https://alice.github.io/minihompy/#/board');
    await page.waitForFunction(()=>window.MinihompySharedIdentity?.state.status==='anonymous' && window.MinihompyAdmin?.state.role==='admin');
    assert.equal(requests.filter(r=>r.url.endsWith('/activation-tickets')).length,activations,'remaining local session must not silently log in centrally');
    await page.evaluate(()=>window.MinihompyAdmin.openLogin());
    await page.waitForURL('**/hub/login.html?**');
    await page.locator('#handle').fill('alice'); await page.locator('#submit').click();
    await page.waitForFunction(()=>location.hostname==='alice.github.io' && window.MinihompySharedIdentity?.state.status==='identified' && window.MinihompyAdmin?.state.role==='admin');
    await page.locator('#login-auth-toggle').click();
    await page.waitForFunction(()=>location.hostname==='alice.github.io' && window.MinihompySharedIdentity?.state.status==='anonymous' && window.MinihompyAdmin?.state.role==='reader');
    await page.reload();
    await page.waitForFunction(()=>window.MinihompySharedIdentity?.state.status==='anonymous' && window.MinihompyAdmin?.state.role==='reader');
    assert.equal(await page.locator('#login-auth-toggle').textContent(),'로그인');
    assert.deepEqual(errors,[]); await page.close();
    console.log('PASS: reload, direct C visit, query/hash preservation, visitor logout, no silent central login, own-site local + central logout.');
  }
  {
    const {page,context,errors}=await contextFor(); await start(page); await chooseAlice(page);
    await page.waitForFunction(()=>!document.querySelector('#password').disabled);
    await page.locator('#password').fill('browser-password'); await page.locator('#submit').click(); await identified(page);
    await context.addInitScript(()=>{
      if(location.hostname!=='central.github.io')return;
      window.blockLogout = true;
      const remove = Storage.prototype.removeItem;
      Storage.prototype.removeItem = function(key){if(window.blockLogout && key==='minihompy.identity.session.v1')throw Error('blocked');return remove.call(this,key);};
    });
    await page.locator('#login-auth-toggle').click(); await page.waitForURL('**/hub/logout.html?**');
    await page.locator('#retry').waitFor({state:'visible'});
    assert.match(await page.locator('#message').textContent(),/저장소/);
    assert.ok(await page.evaluate(()=>localStorage.getItem('minihompy.identity.session.v1')));
    await page.evaluate(()=>{window.blockLogout=false;}); await page.locator('#retry').click();
    await page.waitForFunction(()=>location.hostname==='bob.github.io' && window.MinihompySharedIdentity?.state.status==='anonymous');
    assert.deepEqual(errors,[]); await page.close();
    console.log('PASS: blocked central logout stays on error; retry removes the session and returns anonymous.');
  }
  {
    const {page,context,errors}=await contextFor(); let offline=true;
    await context.route('**/visits/issue',route=>offline ? route.abort('failed') : route.fallback());
    await page.goto('https://bob.github.io/minihompy/?keep=yes#/board');
    await page.waitForURL('**/hub/visit.html?**'); await page.locator('#retry').waitFor({state:'visible'});
    await page.locator('#back').click();
    await page.waitForFunction(()=>location.hostname==='bob.github.io' && window.MinihompySharedIdentity?.state.status==='error');
    assert.equal(new URL(page.url()).search,'?keep=yes'); assert.equal(new URL(page.url()).hash,'#/board');
    offline=false; await page.locator('#visitor-identity-retry').click();
    await page.waitForFunction(()=>location.hostname==='bob.github.io' && window.MinihompySharedIdentity?.state.status==='anonymous');
    assert.deepEqual(errors,[]); await page.close();
    console.log('PASS: central outage returns safely without a redirect loop; explicit retry recovers the original route.');
  }
  {
    await pg.query('update private.identity_sites set login_url=$1 where id=$2', ['https://alice.github.io/minihompy/login/',alice.id]);
    const result=await loginChecks({centralApiUrl:centralApi,centralPageUrl:central+'/',sites:[alice,bob,carol].map((site,index)=>({homepage:`https://${site.handle}.github.io/minihompy/`,projectRef:site.ref,siteId:site.id,handle:site.handle,passwordEnv:`TEST_${index}_PASSWORD`}))},{contextFactory:async()=>(await contextFor()).context,env:{TEST_0_PASSWORD:'browser-password',TEST_1_PASSWORD:'browser-password'}});
    assert.ok(result.every(check=>check.passed));
    console.log('PASS: live-login runner exercised through real browser + local SQL; A/B account switch, additional origin, direct navigation, role isolation and logout.');
  }
  for(const req of requests) {
    if(req.body?.includes('browser-password') || req.body?.includes('"password"')) assert.ok([alice,bob].some(site=>req.url.startsWith(`https://${site.ref}.supabase.co/`)),'Password must stay in personal Supabase');
    if(req.url.startsWith(centralApi)) {assert.ok(!req.body?.includes('refresh-'));assert.ok(!req.body?.includes('private-owner@example.test'));assert.ok(!req.body?.includes('browser-password'));}
    for(const accessToken of tokens.values()) assert.ok(!req.url.includes(accessToken));
  }
  console.log('PASS: browser requests expose neither password nor refresh token/email to central; access tokens stay out of URLs.');
} catch(error) {
  for(const context of contexts)for(const page of context.pages()) console.error('At:',new URL(page.url()).origin+new URL(page.url()).pathname,await page.locator('[role=status]').allTextContents().catch(()=>[]));
  throw error;
} finally {await browser.close();await pg.close();}
