import { spawn } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
export async function deployCentral({ env=process.env, apply=false, fetcher=fetch, runner=spawn, log=console.log }={}) {
  const ref=env.CENTRAL_PROJECT_REF, origin=env.CENTRAL_ORIGIN, page=env.CENTRAL_PAGE_URL;
  if(!/^[a-z]{20}$/.test(ref||''))throw Error('CENTRAL_PROJECT_REF가 필요합니다.');
  const pageUrl=new URL(page), originUrl=new URL(origin);
  if(pageUrl.protocol!=='https:' || pageUrl.origin!==origin || originUrl.origin!==origin || pageUrl.username || pageUrl.password || pageUrl.search || pageUrl.hash)throw Error('중앙 Pages URL/origin을 확인해 주세요.');
  if(!apply){log(`DRY RUN: ${ref} DB v2 확인 → 중앙 Secrets 설정 → identity-api/identity-page 배포`);return;}
  const token=env.SUPABASE_ACCESS_TOKEN, secret=env.CENTRAL_TOKEN_SECRET;
  if(!token || typeof secret!=='string' || Buffer.byteLength(secret)<32)throw Error('Management token과 32바이트 이상의 중앙 전용 서명키가 필요합니다.');
  async function call(path,body){
    let response;
    try {response=await fetcher(`https://api.supabase.com/v1/projects/${ref}/${path}`,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(30000)});}
    catch{throw Error('중앙 관리 API 연결에 실패했습니다.');}
    if(!response.ok)throw Error(`중앙 관리 API 실패 (HTTP ${response.status}).`);
    return response.json();
  }
  const [schema]=await call('database/query',{query:"select exists(select 1 from information_schema.columns where table_schema='private' and table_name='identity_sites' and column_name='verification_status') and to_regprocedure('private.identity_verify_registration(uuid,uuid)') is not null and to_regclass('private.identity_login_attempts') is not null as ready"});
  if(!schema?.ready)throw Error('중앙 v2 마이그레이션을 먼저 적용해야 합니다. Secrets/함수는 변경하지 않았습니다.');
  await call('secrets',[{name:'CENTRAL_TOKEN_SECRET',value:secret},{name:'CENTRAL_ORIGIN',value:origin},{name:'CENTRAL_PAGE_URL',value:page}]);
  for(const name of ['identity-api','identity-page'])await new Promise((done,reject)=>{
    const child=runner('supabase',['functions','deploy',name,'--project-ref',ref,'--use-api','--no-verify-jwt'],{cwd:fileURLToPath(new URL('../',import.meta.url)),env:{...process.env,SUPABASE_ACCESS_TOKEN:token},stdio:'ignore'});
    child.on('error',()=>reject(Error('Supabase CLI를 설치해 주세요.')));
    child.on('close',code=>code===0?done():reject(Error(`${name} 배포 실패. 같은 명령으로 재시도해 주세요.`)));
  });
  log('중앙 함수 배포 완료. Pages 배포와 개인 사이트 재검증을 진행해 주세요.');
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href){
  if(process.argv.slice(2).some(a=>!['--apply','--dry-run'].includes(a)))throw Error('--apply 또는 --dry-run만 지원합니다.');
  deployCentral({apply:process.argv.includes('--apply')&&!process.argv.includes('--dry-run')}).catch(error=>{console.error(error.message);process.exitCode=1;});
}
