import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {deployCentral} from './deploy-functions.mjs';
export async function applyNavigationMigration(query){
 const name='202609230003_member_navigation.sql';
 const sql=await readFile(new URL('../supabase/migrations/'+name,import.meta.url),'utf8');
 const hash=createHash('sha256').update(sql).digest('hex');
 await query('create table if not exists private.navigation_deployments(name text primary key,sha256 text not null);revoke all on private.navigation_deployments from public,anon,authenticated;');
 const rows=await query('select name,sha256 from private.navigation_deployments');
 const prior=rows.find(row=>row.name===name);
 if(prior){if(prior.sha256!==hash)throw Error('Applied navigation migration hash differs');return;}
 const [state]=await query("select to_regprocedure('private.identity_navigation(text,uuid,uuid[],text,uuid,integer)') is not null as exists");
 if(state.exists)throw Error('Untracked navigation function; inspect deployment history');
 await query(`begin;select pg_advisory_xact_lock(87241034);${sql.replace(/^\s*(?:begin|commit);\s*$/gmi,'')}\ninsert into private.navigation_deployments values('${name}','${hash}');commit;`);
}
export async function deployNavigation({env=process.env,apply=false,fetcher=fetch}={}){
 const ref=env.CENTRAL_PROJECT_REF;
 if(!/^[a-z]{20}$/.test(ref||''))throw Error('CENTRAL_PROJECT_REF required');
 if(!apply){console.log('DRY RUN: tracked read-only navigation SQL → central functions; personal Pages follow separately.');return;}
 if(!env.SUPABASE_ACCESS_TOKEN)throw Error('Management token required');
 await applyNavigationMigration(async query=>{
  const response=await fetcher(`https://api.supabase.com/v1/projects/${ref}/database/query`,{method:'POST',headers:{Authorization:'Bearer '+env.SUPABASE_ACCESS_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({query}),redirect:'error',signal:AbortSignal.timeout(30000)});
  if(!response.ok)throw Error('Navigation migration failed: HTTP '+response.status);
  return response.json();
 });
 await deployCentral({env,apply:true,fetcher});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)deployNavigation({apply:process.argv.includes('--apply')}).catch(error=>{console.error(error.message);process.exitCode=1;});
