// Disposable loopback-only PostgreSQL. Never connects to hosted databases.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
const container=execFileSync('docker',['run','--rm','-d','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432','postgres:16-alpine'],{encoding:'utf8'}).trim();
const sleep=ms=>new Promise(r=>setTimeout(r,ms));let pool;const clients=[];
const id=n=>`40000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const member=id(1),site=id(2),sid=id(3),owner=id(4),challenge='c'.repeat(43),delegation='d'.repeat(43);
try{
 const port=Number(execFileSync('docker',['port',container,'5432'],{encoding:'utf8'}).trim().split(':').at(-1));
 pool=new pg.Pool({host:'127.0.0.1',port,user:'postgres',database:'postgres',max:5});
 for(let n=0;;n++){try{await pool.query('select 1');break;}catch(e){if(n>=100)throw e;await sleep(100);}}
 await pool.query('create role anon;create role authenticated;create role service_role bypassrls');
 for(const file of ['202609180001_identity.sql','202609190001_fix_private_schema_permissions.sql','202609230001_verified_identity.sql','202609230002_member_writing.sql','202609230003_member_navigation.sql'])await pool.query(await readFile(new URL('../supabase/migrations/'+file,import.meta.url),'utf8'));
 await pool.query("insert into private.identity_members(id,handle,display_name) values($1,'alice','Alice')",[member]);
 await pool.query("insert into private.identity_sites(id,member_id,origin,base_path,homepage_url,login_url,supabase_project_ref,verification_status) values($1,$2,'https://a.test','/home/','https://a.test/home/','https://a.test/home/login/','aaaaaaaaaaaaaaaaaaaa','verified')",[site,member]);
 await pool.query('insert into private.identity_bindings(site_id,member_id,local_user_id) values($1,$2,$3)',[site,member,owner]);
 await pool.query("insert into private.identity_sessions(id,member_id,site_id,session_version,owner_user_id,expires_at) values($1,$2,$3,1,$4,now()+interval '1 day')",[sid,member,site,owner]);
 const oldProof=(await pool.query("select private.identity_writing_action('issue',$1) result",[{session_id:sid,member_id:member,session_version:1,site_id:site,code_challenge:challenge,return_path:'/home/'}])).rows[0].result;
 const oldGrant=(await pool.query("select private.identity_writing_action('redeem',$1) result",[{session_id:sid,member_id:member,session_version:1,site_id:site,code_challenge:challenge,proof_id:oldProof.id,grant_hash:'v'.repeat(43)}])).rows[0].result;
 assert.equal(oldGrant.active,true);
 const before=(await pool.query('select * from private.identity_writing_grants')).rows[0];
 await pool.query(await readFile(new URL('../supabase/migrations/202609230004_member_sessions.sql',import.meta.url),'utf8'));
 const after=(await pool.query('select * from private.identity_writing_grants')).rows[0];delete after.delegation_hash;assert.deepEqual(after,before);
 assert.equal((await pool.query("select private.identity_writing_action('check',$1) result",[{site_id:site,grant_hash:'v'.repeat(43)}])).rows[0].result.active,true);
 console.log('PASS: upgrade preserves existing v1 grant fields and authorization');
 const a=await pool.connect(),b=await pool.connect();clients.push(a,b);
 const action=async(c,name,args)=>(await c.query('select private.identity_writing_action($1,$2) result',[name,args])).rows[0].result;
 const binding={session_id:sid,member_id:member,session_version:1,site_id:site};
 const proof=await action(a,'issue',{...binding,protocol:2,attempt_id:'visit',code_challenge:challenge,return_path:'/home/'});
 const redeem={...binding,protocol:2,attempt_id:'visit',code_challenge:challenge,proof_id:proof.id,delegation_hash:delegation};
 const redeemed=await Promise.all([action(a,'redeem',{...redeem,grant_hash:'a'.repeat(43)}),action(b,'redeem',{...redeem,grant_hash:'b'.repeat(43)})]);
 assert.equal(redeemed.filter(v=>v.active).length,1);assert.equal(redeemed.filter(v=>v.failure==='PROOF_USED').length,1);
 console.log('PASS: independent PostgreSQL connections consume proof exactly once');
 const renewals=await Promise.all([action(a,'renew',{site_id:site,delegation_hash:delegation,grant_hash:'e'.repeat(43)}),action(b,'renew',{site_id:site,delegation_hash:delegation,grant_hash:'f'.repeat(43)})]);
 assert.equal(renewals.filter(v=>v.active).length,1);assert.equal(renewals.filter(v=>v.failure==='RATE_LIMITED').length,1);
 console.log('PASS: independent renewals serialized and rate limited');
 async function waitLock(pid){for(let i=0;i<100;i++){const r=await pool.query("select wait_event_type from pg_stat_activity where pid=$1",[pid]);if(r.rows[0]?.wait_event_type==='Lock')return;await sleep(10);}throw Error('expected actual row-lock wait');}
 await pool.query('update private.identity_writing_delegations set last_renewed_at=null');
 await a.query('begin');await action(a,'logout',binding);
 const pending=action(b,'renew',{site_id:site,delegation_hash:delegation,grant_hash:'g'.repeat(43)});
 await waitLock(b.processID);await a.query('commit');assert.equal((await pending).failure,'SESSION_REVOKED');
 console.log('PASS: renewal waits on in-flight logout and cannot escape revocation');
 // Isolated fixture reset to exercise the reverse lock ordering.
 await pool.query('update private.identity_sessions set revoked_at=null;update private.identity_writing_delegations set revoked_at=null,last_renewed_at=null');
 await a.query('begin');const fresh=await action(a,'renew',{site_id:site,delegation_hash:delegation,grant_hash:'h'.repeat(43)});assert.equal(fresh.active,true);
 const logout=action(b,'logout',binding);await waitLock(b.processID);await a.query('commit');await logout;
 assert.equal((await action(a,'check',{site_id:site,grant_hash:'h'.repeat(43)})).failure,'SESSION_REVOKED');
 console.log('PASS: logout after renewal invalidates the newly issued grant');

}finally{for(const c of clients){await c.query('rollback').catch(()=>{});c.release();}if(pool)await pool.end();execFileSync('docker',['rm','-f',container],{stdio:'ignore'});}
