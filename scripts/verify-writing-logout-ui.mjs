import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
const source=await readFile(new URL('../public/visit-flow.js',import.meta.url),'utf8');
async function fixture({failure=0,storageFailure=false,session='test-session'}={}){
 const elements=Object.fromEntries(['#message','#retry','#back'].map(k=>[k,{hidden:false,textContent:'',addEventListener(event,fn){this.click=fn;}}]));
 const state={failure,storageFailure,session,calls:[],redirect:null};
 const flow={sessionKey:'session',async post(base,path,body){state.calls.push({path,body});if(path==='sessions/logout'&&state.failure){const e=Error('server unavailable');e.status=state.failure;throw e;}return path==='visits/issue'?{return_url:'https://site.test/home/'}:{revoked:true};}};
 vm.runInNewContext(source,{window:{MinihompyLoginFlow:flow,MINIHOMPY_CENTRAL_CONFIG:{apiBaseUrl:'https://central.test'}},URLSearchParams,
  location:{search:'?site_id=test',replace(url){state.redirect=url;}},history:{length:1},
  localStorage:{getItem(){return state.session;},removeItem(){if(state.storageFailure)throw Error('storage');state.session=null;}},
  document:{body:{dataset:{action:'logout'}},querySelector:k=>elements[k]}});
 await new Promise(setImmediate);return {state,elements};
}
{
 const {state,elements}=await fixture({failure:503});
 assert.equal(state.session,'test-session');assert.equal(state.redirect,null);assert.equal(elements['#retry'].hidden,false);
 state.failure=0;await elements['#retry'].click();
 assert.equal(state.session,null);assert.equal(state.redirect,'https://site.test/home/');
 assert.deepEqual(state.calls.map(c=>c.path),['sessions/logout','sessions/logout','visits/issue']);
 assert.equal(state.calls.at(-1).body.central_session,null);
}
{
 const {state,elements}=await fixture({storageFailure:true});assert.equal(state.redirect,null);assert.equal(state.session,'test-session');
 state.storageFailure=false;await elements['#retry'].click();assert.equal(state.session,null);assert.equal(state.calls.filter(c=>c.path==='sessions/logout').length,2);
}
for(const config of [{failure:401},{session:null}]){
 const {state}=await fixture(config);assert.equal(state.session,null);assert.equal(state.redirect,'https://site.test/home/');
}
console.log('PASS: logout revokes before clearing, fails closed on server/storage errors, retries, and supports expired/legacy credentials.');
