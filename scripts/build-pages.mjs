import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
const root=new URL('../',import.meta.url), destination=new URL('_site/',root);
await rm(destination,{recursive:true,force:true});await mkdir(destination,{recursive:true});
const files=['config.js','login.html','login.js','login.css','login-flow.js','complete.html','complete.js','visit.html','logout.html','visit-flow.js','writing.html','writing-flow.js'];
for(const file of files)await cp(new URL('public/'+file,root),new URL(file,destination));
await writeFile(new URL('.nojekyll',destination),'');
console.log('Prepared central Pages with explicit runtime allowlist.');
