// Exercise the built production MCP registry/dispatch without any API access.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import {test,before,after} from 'node:test';
let child,lines,id=0;const pending=new Map();
function rpc(method,params){
 const requestId=++id;
 const result=new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>{pending.delete(requestId);reject(new Error(`timeout ${method}`));},5000);
  pending.set(requestId,reply=>{clearTimeout(timer);resolve(reply);});
 });
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',id:requestId,method,params})+'\n');return result;
}
before(async()=>{
 child=spawn(process.execPath,[fileURLToPath(new URL('../dist/index.cjs',import.meta.url))],{stdio:['pipe','pipe','ignore'],env:{PATH:process.env.PATH}});
 lines=createInterface({input:child.stdout});lines.on('line',line=>{const reply=JSON.parse(line),resolve=pending.get(reply.id);if(resolve){pending.delete(reply.id);resolve(reply);}});
 const reply=await rpc('initialize',{protocolVersion:'2024-11-05',capabilities:{},clientInfo:{name:'guard-fixture',version:'1'}});assert(!reply.error);
 child.stdin.write(JSON.stringify({jsonrpc:'2.0',method:'notifications/initialized'})+'\n');
});
after(()=>{child?.kill();lines?.close();});
for(const name of ['get_prevalence','get_entity_risk_timeline','lookup_ioc','lookup_ip','get_entity_context'])test(`${name} cannot be listed or dispatched`,async()=>{
 const {result}=await rpc('tools/list',{});assert(!result.tools.some(t=>t.name===name));
 const reply=await rpc('tools/call',{name,arguments:{}});assert.match(JSON.stringify(reply),/Retired cell tool/);
});
test('public catalog explains discovery, stamp selection and server-authenticated budgets',async()=>{
 const {result}=await rpc('tools/list',{});const tools=result.tools;
 const lake=tools.find(t=>t.name==='lake_sql');assert(!lake.description.includes('b12.'));assert(lake.description.includes('Omit sql'));
 assert(lake.description.includes('returns the first stamp per row; use the artifact_type variant for IPs vs domains'));
 for(const name of ['prevalence','risk_scores','resolve_identity','lookup']){
  const tool=tools.find(t=>t.name===name);assert(tool.inputSchema.required.includes('reason'));assert(tool.description.includes('6 calls per authenticated API key per rolling hour'));
 }
});
