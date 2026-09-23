import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { validateTargets, preflight } from './verify-live-identity.mjs';
const c=JSON.parse(await readFile(new URL('./live-targets.json',import.meta.url),'utf8'));
assert.throws(()=>validateTargets({...c,sites:[c.sites[0],{...c.sites[1],homepage:c.sites[0].homepage}]}),/origins/);
assert.throws(()=>validateTargets({...c,sites:[c.sites[0],{...c.sites[1],projectRef:c.sites[0].projectRef}]}),/projects/);
assert.throws(()=>validateTargets({...c,centralApiUrl:'https://user:secret@example.test/api'}),/credentials/);
let stale=false,calls=0;
const fetcher=async(url,options)=>{
  calls++;assert.equal(options.method,undefined);assert.equal(options.body,undefined);assert.equal(options.headers,undefined);
  if(url===c.centralApiUrl+'/health')return Response.json(stale?{status:'ok'}:{identity_protocol:2});
  if(url.startsWith(c.centralApiUrl+'/directory?')){const site=c.sites.find(s=>new URL(url).searchParams.get('handle')===s.handle);return Response.json({items:[{handle:site.handle,homepage_url:site.homepage}]});}
  if(url.startsWith(c.centralPageUrl)){
    const name=url.slice(c.centralPageUrl.length);
    if(name==='config.js')return new Response(JSON.stringify(c));
    if(stale && name==='complete.js')return new Response('old implementation',{status:200});
    return new Response(await readFile(new URL('../public/'+name,import.meta.url),'utf8'));
  }
  const site=c.sites.find(s=>url.startsWith(s.homepage));assert.ok(site);
  let name=url.slice(site.homepage.length);
  if(!name)return new Response('<html>site</html>');
  if(name==='supabase-config.js')return new Response(JSON.stringify({url:'https://'+site.projectRef+'.supabase.co'+(stale && site===c.sites[1]?'/rest/v1':'')}));
  if(name==='visitor-identity-config.js')return new Response(JSON.stringify({...site,enabled:true,centralApiUrl:c.centralApiUrl,centralPageUrl:c.centralPageUrl.replace(/\/$/,'')}));
  if(name==='login/')name='login/index.html';
  return new Response(await readFile(resolve('../cyworld',name),'utf8'));
};
const good=await preflight(c,{fetcher});assert.equal(good.length,28);assert.ok(good.every(c=>c.passed));assert.equal(calls,28);
stale=true;const outdated=await preflight(c,{fetcher});assert.equal(outdated.filter(c=>!c.passed).length,3,'HTTP 200 is insufficient for old API/runtime or malformed project base URL');
const offline=await preflight(c,{fetcher:async()=>{throw Error('private token should never enter report');}});assert.ok(offline.every(c=>!c.passed));assert.ok(!JSON.stringify(offline).includes('private token'));
console.log('PASS: live preflight requires distinct origins/projects, current runtime hashes and v2 API; GET-only, stale/failed responses fail closed without secrets.');
