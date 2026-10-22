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
 if(capture.success){expect(result.data?.prevalence_semantics).toBe('prevalence at ingest time (stamp)');expect(result.data?.data).toMatchObject(capture.result);}
 expect(fetch).toHaveBeenCalledTimes(2);
});
it('keeps the flattened example inside the single-table window template and probes all six positions',()=>{
 const sql=readFileSync(new URL('../../../docs/rare-artifacts-by-stamp.sql',import.meta.url),'utf8');
 expect(sql).toContain('WHERE {window}');expect(sql).not.toMatch(/FROM\s*\(/i);
 for(let i=1;i<=6;i++){expect(sql).toContain(`enrichments[${i}]['name']`);expect(sql).toContain(`enrichments[${i}]['provider']`);}
 expect(sql).toContain('BETWEEN 1 AND 2');
});
