import assert from 'node:assert/strict';
import {createIdentityDb} from './helpers/identity-db.mjs';
import {applyNavigationMigration} from './deploy-navigation.mjs';
const {pg}=await createIdentityDb();
try {
 await pg.exec('reset role;drop function private.identity_navigation(text,uuid,uuid[],text,uuid,integer)');
 const query=async sql=>(await pg.query(sql)).rows;
 // Multi-statement migration uses exec, retaining SELECT rows for the guards.
 const run=async sql=>/^(create|begin)/i.test(sql)?(await pg.exec(sql),[]):query(sql);
 await applyNavigationMigration(run);await applyNavigationMigration(run);
 assert.equal((await query('select * from private.navigation_deployments')).length,1);
 await pg.exec("update private.navigation_deployments set sha256='changed'");
 await assert.rejects(()=>applyNavigationMigration(run),/hash differs/);
 await pg.exec('truncate private.navigation_deployments');
 await assert.rejects(()=>applyNavigationMigration(run),/Untracked/);
 console.log('PASS: navigation migration first install, repeat, hash drift and untracked function guards');
}finally{await pg.close();}
