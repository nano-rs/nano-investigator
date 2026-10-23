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
for(const name of ['get_prevalence','get_entity_risk_timeline','lookup_ioc','lookup_ip','get_entity_context','get_rare_artifacts','get_new_artifacts','get_risky_entities','get_risk_overview','get_entity_risk_activity'])test(`${name} cannot be listed or dispatched`,async()=>{
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

test('playbooks, lake guide and shift briefing use stamps before heavy exceptions',async()=>{
 const retired=/get_prevalence|get_entity_risk_timeline|lookup_ioc|get_entity_context|lookup_ip|get_risky_entities|get_rare_artifacts|get_new_artifacts|get_risk_overview|get_entity_risk_activity/;
 const listed=await rpc('resources/list',{});
 const resources=listed.result?.resources ?? listed.resources;
 const guides=resources.filter(r=>r.uri==='nano://sql-guide'||r.uri.startsWith('nanosiem://reference/playbooks/'));
 assert.equal(guides.length,8);
 for(const {uri} of guides){
  const reply=await rpc('resources/read',{uri});const result=reply.result ?? reply;
  const text=result.contents.map(c=>c.text).join('\n');assert(!retired.test(text),uri);assert(text.includes('lake_sql'),uri);assert(text.includes('reason'),uri);
 }
 const reply=await rpc('prompts/get',{name:'morning_briefing',arguments:{hours:'24'}});const result=reply.result ?? reply;
 const text=result.messages.map(m=>m.content.text).join('\n');assert(!retired.test(text));assert(text.includes('stamps first'));assert(text.includes('risk_scores with reason and start/end'));
});
