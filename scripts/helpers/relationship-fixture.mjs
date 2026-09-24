import {createHash,randomUUID} from 'node:crypto';
export const id=n=>`70000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
export const member=n=>id(n),site=n=>id(100+n),session=n=>id(200+n);
export const hash=s=>createHash('sha256').update(s).digest('base64url');
export async function seedRelationships(pg,count=6){
 for(let n=1;n<=count;n++){
  await pg.query("insert into private.identity_members(id,handle,display_name) values($1,$2,$3)",[member(n),'member'+n,'Member '+n]);
  await pg.query("insert into private.identity_sites(id,member_id,origin,base_path,homepage_url,login_url,supabase_project_ref,verification_status) values($1,$2,$3,'/home/',$4,$5,$6,'verified')",[site(n),member(n),`https://m${n}.test`,`https://m${n}.test/home/`,`https://m${n}.test/home/login/`,'project'+n]);
  await pg.query('insert into private.identity_bindings(site_id,member_id,local_user_id) values($1,$2,$3)',[site(n),member(n),id(300+n)]);
  await pg.query("insert into private.identity_sessions(id,member_id,site_id,session_version,owner_user_id,expires_at) values($1,$2,$3,1,$4,clock_timestamp()+interval '1 day')",[session(n),member(n),site(n),id(300+n)]);
 }
}
export async function grantFor(pg,n,target=2,cs=session(n)){
 const args={session_id:cs,member_id:member(n),session_version:1,site_id:site(target),code_challenge:'c'.repeat(43),return_path:'/home/',protocol:2,attempt_id:randomUUID()};
 const p=(await pg.query("select private.identity_writing_action('issue',$1) result",[args])).rows[0].result;
 if(p.failure)throw Error(JSON.stringify(p));
 const grant_hash=hash(randomUUID());
 const g=(await pg.query("select private.identity_writing_action('redeem',$1) result",[{...args,proof_id:p.id,grant_hash,delegation_hash:hash(randomUUID())}])).rows[0].result;
 if(g.failure)throw Error(JSON.stringify(g));
 return {site_id:site(target),grant_hash};
}
export const rpc=async(pg,action,args)=>(await pg.query('select private.identity_relationship_action($1,$2) result',[action,args])).rows[0].result;
export const command=(target,action,revision,request_id,extra={})=>({target_member_id:member(target),action,expected_revision:revision,operation_id:randomUUID(),...(request_id?{request_id}:{}),...extra});
