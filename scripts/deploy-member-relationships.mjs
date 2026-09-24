// Upgrade an existing central installation without rotating its signing secret.
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
export async function applyMemberRelationships({query}) {
 const name='202609240001_member_relationships.sql',sql=await readFile(new URL('../supabase/migrations/'+name,import.meta.url),'utf8'),hash=createHash('sha256').update(sql).digest('hex');
 const [schema]=await query("select to_regclass('private.identity_writing_delegations') is not null as ready,to_regclass('private.identity_relationships') is not null as upgraded");
 if(!schema.ready)throw Error('Deploy existing central sessions first');
 await query('create table if not exists private.member_writing_deployments(name text primary key,sha256 text not null);revoke all on private.member_writing_deployments from public,anon,authenticated;');
 const rows=await query('select name,sha256 from private.member_writing_deployments');const prior=rows.find(r=>r.name===name);
 if(prior){if(prior.sha256!==hash||!schema.upgraded)throw Error('Applied central relationship migration hash differs');return;}
 if(schema.upgraded)throw Error('Untracked central relationship schema');
 await query(`begin;select pg_advisory_xact_lock(87241033);${sql.replace(/^\s*(?:begin|commit);\s*$/gmi,'')}\ninsert into private.member_writing_deployments values('${name}','${hash}');commit;`);
}
export async function deployMemberRelationships({env=process.env,apply=false,fetcher=fetch,runner=spawn}={}){
 const ref=env.CENTRAL_PROJECT_REF;if(!/^[a-z]{20}$/.test(ref||''))throw Error('CENTRAL_PROJECT_REF required');
 if(!apply){console.log('DRY RUN: tracked relationship migration → identity-api/identity-page; existing secrets preserved; Pages follows separately');return;}
 if(!env.SUPABASE_ACCESS_TOKEN)throw Error('Management token required');
 await applyMemberRelationships({query:async query=>{const r=await fetcher(`https://api.supabase.com/v1/projects/${ref}/database/query`,{method:'POST',headers:{Authorization:'Bearer '+env.SUPABASE_ACCESS_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({query}),redirect:'error',signal:AbortSignal.timeout(30000)});if(!r.ok)throw Error('Central query HTTP '+r.status);return r.json();}});
 for(const name of ['identity-api','identity-page'])await new Promise((done,reject)=>{const child=runner('supabase',['functions','deploy',name,'--project-ref',ref,'--use-api','--no-verify-jwt'],{cwd:fileURLToPath(new URL('../',import.meta.url)),env:{...process.env,SUPABASE_ACCESS_TOKEN:env.SUPABASE_ACCESS_TOKEN},stdio:'ignore'});child.on('error',()=>reject(Error('Supabase CLI unavailable')));child.on('close',code=>code===0?done():reject(Error(name+' deploy failed')));});
 const health=await fetcher(`https://${ref}.supabase.co/functions/v1/identity-api/health`,{redirect:'error',signal:AbortSignal.timeout(30000)});
 if(!health.ok||(await health.json()).relationship_protocol!==1)throw Error('Central relationship health probe failed; retain DB and retry');
 console.log('Central relationship migration/functions deployed; existing signing key preserved');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)deployMemberRelationships({apply:process.argv.includes('--apply')}).catch(e=>{console.error(e.message);process.exitCode=1;});
