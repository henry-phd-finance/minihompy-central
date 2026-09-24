// Local dry-run by default. Existing central signing secrets are never changed.
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
export const friendVisibilityMigration='202609240002_friend_visibility.sql';
export async function applyFriendVisibility({query}){
 const name=friendVisibilityMigration,sql=await readFile(new URL('../supabase/migrations/'+name,import.meta.url),'utf8'),hash=createHash('sha256').update(sql).digest('hex');
 const [state]=await query("select to_regclass('private.identity_relationships') is not null as ready,to_regprocedure('private.identity_read_context(jsonb)') is not null as installed");
 if(!state?.ready)throw Error('Central relationships must be installed first');
 await query('create table if not exists private.member_writing_deployments(name text primary key,sha256 text not null);revoke all on private.member_writing_deployments from public,anon,authenticated,service_role;');
 const rows=await query('select name,sha256 from private.member_writing_deployments'),prior=rows.find(r=>r.name===name);
 if(prior){if(prior.sha256!==hash||!state.installed)throw Error('Central visibility history/hash differs');return;}
 if(state.installed)throw Error('Untracked central visibility schema; do not adopt automatically');
 await query(`begin;select pg_advisory_xact_lock(87241033);${sql.replace(/^\s*(?:begin|commit);\s*$/gmi,'')}\ninsert into private.member_writing_deployments values('${name}','${hash}');commit;`);
}
export async function deployFriendVisibility({env=process.env,apply=false,fetcher=fetch,runner=spawn,log=console.log}={}){
 const ref=env.CENTRAL_PROJECT_REF;if(!/^[a-z]{20}$/.test(ref||''))throw Error('CENTRAL_PROJECT_REF required');
 if(!apply){log('DRY RUN: central tracked visibility migration → identity-api/identity-page → capability probe; no network, secret or Pages changes');return;}
 if(!env.SUPABASE_ACCESS_TOKEN)throw Error('Management token required');
 await applyFriendVisibility({query:async query=>{const r=await fetcher(`https://api.supabase.com/v1/projects/${ref}/database/query`,{method:'POST',headers:{Authorization:'Bearer '+env.SUPABASE_ACCESS_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({query}),redirect:'error',signal:AbortSignal.timeout(30000)});if(!r.ok)throw Error('Central query failed: '+r.status);return r.json();}});
 for(const name of ['identity-api','identity-page'])await new Promise((done,reject)=>{const child=runner('supabase',['functions','deploy',name,'--project-ref',ref,'--use-api','--no-verify-jwt'],{cwd:fileURLToPath(new URL('../',import.meta.url)),env:{...process.env,SUPABASE_ACCESS_TOKEN:env.SUPABASE_ACCESS_TOKEN},stdio:'ignore'});child.on('error',()=>reject(Error('Supabase CLI unavailable')));child.on('close',code=>code===0?done():reject(Error(name+' deploy failed')));});
 const r=await fetcher(`https://${ref}.supabase.co/functions/v1/identity-api/health`,{redirect:'error',cache:'no-store',signal:AbortSignal.timeout(30000)}),h=await r.json();
 if(!r.ok||h.friend_visibility_protocol!==1||h.relationship_protocol!==1||h.member_session_protocol!==2)throw Error('Central visibility capability probe failed; retain DB and retry');
 log('Central visibility ready; existing identities/relationships/signing secrets preserved. Prepare personal A next.');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)deployFriendVisibility({apply:process.argv.includes('--apply')}).catch(e=>{console.error(e.message);process.exitCode=1;});
