import {readFile} from 'node:fs/promises';import {createHash} from 'node:crypto';import {pathToFileURL} from 'node:url';import {deployCentral} from './deploy-functions.mjs';
export async function deployMemberWriting({env=process.env,apply=false,fetcher=fetch}={}){
 const ref=env.CENTRAL_PROJECT_REF;if(!/^[a-z]{20}$/.test(ref||''))throw Error('CENTRAL_PROJECT_REF is required');
 if(!apply){console.log('DRY RUN: tracked writing migration → central functions; Pages follows separately.');return;}
 if(!env.SUPABASE_ACCESS_TOKEN)throw Error('Management access token required');
 const name='202609230002_member_writing.sql',sql=await readFile(new URL('../supabase/migrations/'+name,import.meta.url),'utf8'),hash=createHash('sha256').update(sql).digest('hex');
 async function query(query){const r=await fetcher(`https://api.supabase.com/v1/projects/${ref}/database/query`,{method:'POST',headers:{Authorization:'Bearer '+env.SUPABASE_ACCESS_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({query}),redirect:'error',signal:AbortSignal.timeout(30000)});if(!r.ok)throw Error('Central migration request failed: HTTP '+r.status);return r.json();}
 await query('create table if not exists private.member_writing_deployments(name text primary key,sha256 text not null);revoke all on private.member_writing_deployments from public,anon,authenticated;');
 const rows=await query('select name,sha256 from private.member_writing_deployments');const prior=rows.find(r=>r.name===name);
 if(prior){if(prior.sha256!==hash)throw Error('Applied central migration hash differs');}
 else{
  const [state]=await query("select to_regclass('private.identity_sessions') is not null as exists");if(state.exists)throw Error('Untracked writing schema; inspect before retry');
  await query(`begin;select pg_advisory_xact_lock(87241033);${sql.replace(/^\s*(?:begin|commit);\s*$/gmi,'')}\ninsert into private.member_writing_deployments values('${name}','${hash}');commit;`);
 }
 await deployCentral({env,apply:true,fetcher});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)deployMemberWriting({apply:process.argv.includes('--apply')}).catch(e=>{console.error(e.message);process.exitCode=1;});
