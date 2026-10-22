import {readFileSync,readdirSync} from 'node:fs';
import {expect,it,vi,afterEach} from 'vitest';
import {NanosiemClient} from './client.js';
import {resolveAgentWindow} from './agent-window.js';
const dir = new URL('./fixtures/basin-rows/', import.meta.url);
afterEach(()=>vi.unstubAllGlobals());
it.each(readdirSync(dir).filter(n=>n.endsWith('.json')))('passes the real Basin response %s without inventing a row shape',async file=>{
 const capture=JSON.parse(readFileSync(new URL(file,dir),'utf8'));
 const args={start:'2026-10-15',end:'2026-10-22',sql:'SELECT enrichments FROM b12.conduit_proxy WHERE {window}'};
 const window=resolveAgentWindow(args);
 const fetch=vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({agent_lane:{tenant_id:'00000000-0000-4000-8000-00000000000a'}})))
   .mockResolvedValueOnce(new Response(JSON.stringify({...capture.result,window}),{status:capture.success?200:400}));
 vi.stubGlobal('fetch',fetch);
 const result=await new NanosiemClient({apiUrl:'https://fixture.invalid/t/a',apiKey:'key-a'}).agentTool('lake_sql',args);
 expect(result.success).toBe(capture.success);
 if(capture.success){expect(result.data?.prevalence_semantics).toBeUndefined();expect(result.data?.data).toMatchObject(capture.result);}
 expect(fetch).toHaveBeenCalledTimes(2);
});
it('keeps the flattened example inside the single-table window template and probes all six positions',()=>{
 const sql=readFileSync(new URL('../../../docs/rare-artifacts-by-stamp.sql',import.meta.url),'utf8');
 expect(sql).toContain('WHERE {window}');expect(sql).not.toMatch(/FROM\s*\(/i);
 for(let i=1;i<=6;i++){expect(sql).toContain(`enrichments[${i}]['name']`);expect(sql).toContain(`enrichments[${i}]['provider']`);}
 expect(sql).toContain('BETWEEN 1 AND 2');
});

it('IP variant selects its own stamp in all five CASE expressions',()=>{
 const sql=readFileSync(new URL('../../../docs/rare-ips-by-stamp.sql',import.meta.url),'utf8');
 expect(sql).not.toMatch(/FROM\s*\(/i);expect(sql).toContain('FROM <namespace>.<table>');
 for(let i=1;i<=6;i++)expect(sql.match(new RegExp(`enrichments\\[${i}\\]\\['data'\\]\\['artifact_type'\\] = 'ip_address'`,'g'))).toHaveLength(5);
});

it('the captured typed IP stamp follows the first domain stamp',()=>{
 const capture=JSON.parse(readFileSync(new URL('select_enrichments_with_prevalence_proxy.json',dir),'utf8'));
 const row=capture.result.rows.find((r: {enrichments: Array<{name:string;data?:{artifact_type?:string}}>})=>r.enrichments.some(e=>e.name==='prevalence' && e.data?.artifact_type==='ip_address'));
 const stamps=row.enrichments.filter((e:{name:string})=>e.name==='prevalence');
 expect(stamps[0].data.artifact_type).toBe('subdomain');expect(stamps.find((e:{data?:{artifact_type?:string}})=>e.data?.artifact_type==='ip_address').value).toBe('151.101.1.67');
});
