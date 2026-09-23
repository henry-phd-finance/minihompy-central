import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createIdentityDb } from './helpers/identity-db.mjs';
import { handleIdentityApiRequest } from '../supabase/functions/identity-api/handler.js';
const {pg, db} = await createIdentityDb();
const id = n => `20000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const options = {supabaseClient: db, allowedOrigins: new Set(['https://a.github.io'])};
let groups = 0;
async function group(name, fn) { await fn(); console.log(`PASS ${++groups}: ${name}`); }
async function call(path, status = 200, overrides = {}, method = 'GET') {
  const res = await handleIdentityApiRequest(new Request('https://central.test'+path, {method, headers:{Origin:'https://a.github.io'}}), {...options,...overrides});
  const body = await res.json(); assert.equal(res.status,status,JSON.stringify(body));
  if (status !== 403) assert.equal(res.headers.get('Cache-Control'),'no-store');
  return body;
}
try {
  for (let n=1;n<=65;n++) {
    await pg.query('insert into private.identity_members(id,handle,display_name) values($1,$2,$3)',[id(n),`user_${String(n).padStart(3,'0')}`,'같은 이름']);
    await pg.query("insert into private.identity_sites(id,member_id,origin,base_path,homepage_url,login_url,supabase_project_ref,verification_status) values($1,$2,$3,'/home/',$4,$5,$6,'verified')",[id(1000+n),id(n),`https://user${n}.github.io`,`https://user${n}.github.io/home/`,`https://user${n}.github.io/home/login/`,`project_${n}`]);
  }
  await group('repeatable read-only migration preserves existing registry rows',async()=>{
    const snapshot=async()=> (await pg.query("select (select jsonb_agg(to_jsonb(m) order by id) from private.identity_members m) as members, (select jsonb_agg(to_jsonb(s) order by id) from private.identity_sites s) as sites")).rows;
    const before=await snapshot();
    await pg.exec('reset role');
    await pg.exec(await readFile(new URL('../supabase/migrations/202609230003_member_navigation.sql',import.meta.url),'utf8'));
    await pg.exec('set role service_role');
    assert.deepEqual(await snapshot(),before);
  });
  await group('site owner, stable member identity and explicit public fields',async()=>{
    const {item} = await call(`/navigation/site?site_id=${id(1001)}`);
    assert.equal(item.id,id(1)); assert.equal(item.site_id,id(1001));
    assert.deepEqual(Object.keys(item).sort(),['display_name','handle','homepage_url','id','site_id']);
    for(const prefix of ['/identity-api','/functions/v1/identity-api']) assert.deepEqual(await call(`${prefix}/navigation/site?site_id=${id(1001)}`),{item});
    await call(`/navigation/site?site_id=${id(999)}`,404);
  });
  await group('deduplicated batch, latest URL and unknown member',async()=>{
    let b=await call(`/navigation/members?member_ids=${id(1)},${id(1)},${id(2)},${id(999)}`); assert.equal(b.items.length,2);
    await pg.query("update private.identity_sites set origin='https://moved.github.io',homepage_url='https://moved.github.io/home/' where member_id=$1",[id(1)]);
    b=await call(`/navigation/members?member_ids=${id(1)}`); assert.equal(b.items[0].homepage_url,'https://moved.github.io/home/');
  });
  await group('filter before pagination: inactive, unverified, unsafe and unbound destinations',async()=>{
    await pg.query("update private.identity_members set status='suspended' where id=$1",[id(3)]);
    await pg.query("update private.identity_sites set status='suspended' where member_id=$1",[id(4)]);
    await pg.query("update private.identity_sites set verification_status='needs_reverification' where member_id=$1",[id(5)]);
    const urls=['http://bad.example/','https://user:pass@bad.example/','javascript:alert(1)','https://different.example/home/','https://user10.github.io/home/?token=bad','https://user11.github.io/home/#token','https://user12.github.io\\evil/'];
    for(let i=0;i<urls.length;i++) await pg.query('update private.identity_sites set homepage_url=$1 where member_id=$2',[urls[i],id(6+i)]);
    for(let n=3;n<=12;n++) {
      await call(`/navigation/site?site_id=${id(1000+n)}`,404);
      assert.deepEqual((await call(`/navigation/members?member_ids=${id(n)}`)).items,[]);
    }
    const found=[]; let cursor=null;
    do {const page=await call('/directory?limit=7'+(cursor?`&after=${cursor}`:'')); assert.ok(page.items.length<=7);found.push(...page.items.map(r=>r.id));cursor=page.next_cursor;}while(cursor);
    assert.deepEqual(found,Array.from({length:65},(_,i)=>i+1).filter(n=>n<3||n>12).map(id));
    const defaultPage=await call('/directory');assert.equal(defaultPage.items.length,20);assert.ok(defaultPage.next_cursor);
    const search=await call('/directory?q=user_06&limit=3');assert.equal(search.items.length,3);assert.ok(search.next_cursor);
    assert.deepEqual((await call('/directory?q=%25%25&limit=20')).items,[]);
    assert.deepEqual((await call('/directory?limit=20&after='+id(999))).items,[]);
  });
  await group('random samples entire eligible population and excludes current site',async()=>{
    await pg.query('select setseed(0.42)');
    const found=new Set();
    for(let n=0;n<100;n++) {const {item}=await call(`/navigation/random?site_id=${id(1001)}`);assert.notEqual(item.id,id(1));assert.ok(Number(item.id.slice(-12))<3||Number(item.id.slice(-12))>12);found.add(item.id);}
    assert.ok([...found].some(value=>Number(value.slice(-12))>50),'must not sample only first directory page');
    await pg.query("update private.identity_sites set status='suspended' where member_id not in ($1,$2)",[id(1),id(65)]);
    assert.equal((await call(`/navigation/random?site_id=${id(1001)}`)).item.id,id(65));
    await pg.query("update private.identity_sites set status='suspended' where member_id=$1",[id(65)]);
    assert.equal((await call(`/navigation/random?site_id=${id(1001)}`)).item,null);
    await pg.query("update private.identity_sites set status='suspended'");
    assert.equal((await call(`/navigation/random?site_id=${id(1001)}`)).item,null);
  });
  await group('bounded inputs, CORS, methods and database failure distinct from empty',async()=>{
    for(const path of ['/navigation/site','/navigation/site?site_id=oops','/navigation/random?site_id=oops','/navigation/members?member_ids=',`/navigation/members?member_ids=${Array(51).fill(id(1)).join(',')}`,'/directory?limit=0','/directory?limit=51','/directory?limit=1.5','/directory?after=oops','/directory?q=a&limit=20','/directory?q=aa&q=bb&limit=20','/directory?q=aa&query=bb&limit=20','/directory?limit=20&handle=user_001',`/navigation/site?site_id=${id(1001)}&extra=x`]) await call(path,400);
    await call('/navigation/site',405,{},'POST');
    await call('/directory',403,{allowedOrigins:new Set()});
    await call('/directory',503,{supabaseClient:{rpc:async()=>({error:{message:'secret failure'},data:null})}});
    const res=await handleIdentityApiRequest(new Request('https://central.test/navigation/site',{method:'OPTIONS',headers:{Origin:'https://a.github.io'}}),options);assert.equal(res.status,204);
  });
  await group('RPC not executable by anonymous or authenticated roles',async()=>{
    for(const role of ['anon','authenticated']) {
      await pg.exec(`reset role; set role ${role}`);
      await assert.rejects(pg.query("select private.identity_navigation('list')"),/permission denied/);
    }
    await pg.exec('reset role; set role service_role');
    await assert.rejects(pg.query("select private.identity_navigation('list',p_limit=>10000)"),/Invalid navigation/);
  });
  console.log(`PASS: ${groups} navigation groups (actual PostgreSQL, no deployment).`);
} finally { await pg.close(); }
