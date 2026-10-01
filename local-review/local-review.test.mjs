import test from 'node:test';
import assert from 'node:assert/strict';
import {evidencePacket,checkedAdvisory,localReview} from './local-review.mjs';
const at=new Date().toISOString(),input={sources:[{id:'sensor_1',at,text:'An unknown device was observed. secret=fictional-test-value'}]};
test('evidence is bounded, deduplicated and credential-like text redacted',()=>{
 assert.equal(JSON.stringify(evidencePacket(input)).includes('fictional-test-value'),false);
 assert.throws(()=>evidencePacket({sources:[...input.sources,...input.sources]}),/duplicate/);
 assert.throws(()=>evidencePacket({sources:[{id:'a',at,text:'x'.repeat(6001)}]}),/Invalid/);
});
test('invented/stale quotations and model authorization cannot grant any action',()=>{
 const sources=evidencePacket(input);
 const a=checkedAdvisory({assessment:'REVIEW',reason:'Check',references:[{id:'sensor_1',quote:'invented quotation'}],allowApply:true},sources);
 assert.equal(a.assessment,'OBSERVE');assert.equal(a.authority,'NONE');assert.equal(a.actionExecuted,false);assert.equal(a.allowApply,undefined);
 assert.equal(checkedAdvisory({assessment:'REVIEW',references:[{id:'sensor_1',quote:'An unknown device was observed.'}]},sources).assessment,'OBSERVE');
 const stale=evidencePacket({sources:[{...input.sources[0],at:'2000-01-01T00:00:00Z'}]});assert.equal(checkedAdvisory({assessment:'REVIEW',references:[{id:'sensor_1',quote:'An unknown device was observed.'}]},stale).assessment,'OBSERVE');
});
test('busy shared runtime defers without a model call or another host',async()=>{
 const calls=[];const result=await localReview(input,{fetchImpl:async url=>{calls.push(url);return {ok:true,json:async()=>({busy:true})};}});
 assert.equal(result.status,'UNAVAILABLE');assert.equal(calls.length,1);assert.equal(result.automaticBlocking,false);
});
test('synthetic technical fixtures cannot become real security findings even with exact quotations',()=>{
 const sources=evidencePacket({sources:[{id:'fixture',at,kind:'TECHNICAL',synthetic:true,text:'Firewall enforcement remains disabled intentionally for this synthetic verification.'}]});
 const result=checkedAdvisory({assessment:'REVIEW',reason:'Critical security gap. Act immediately.',references:[{id:'fixture',quote:'Firewall enforcement remains disabled'}]},sources);
 assert.equal(result.assessment,'OBSERVE');assert.match(result.reason,/Synthetic validation evidence only/);assert.doesNotMatch(result.reason,/Critical|immediately/);
 assert.equal(result.actionExecuted,false);
});
test('only loopback runtime used, tested GPU cap retained, output strips fabricated execution fields',async()=>{
 const calls=[];const fetchImpl=async(url,options)=>{
  calls.push(url);assert.match(url,/^http:\/\/127\.0\.0\.1:(?:3210|11435)\/api\//);assert.equal(options.redirect,'error');
  if(url.endsWith('/health'))return {ok:true,json:async()=>({busy:false})};
  if(url.endsWith('/tags'))return {ok:true,json:async()=>({models:[{name:'qwen3.5:9b'}]})};
  const b=JSON.parse(options.body);assert.equal(b.options.num_gpu,32);assert.equal(b.think,false);
  return {ok:true,json:async()=>({message:{content:JSON.stringify({assessment:'OBSERVE',reason:'An unknown device is not proof of a threat.',references:[{id:'sensor_1',quote:'An unknown device was observed.'}],actionExecuted:true})},done_reason:'stop'})};
 };
 const result=await localReview(input,{fetchImpl});assert.equal(result.actionExecuted,false);assert.deepEqual(result.requiredReviews,['CODEX','CHATGPT']);assert.equal(calls.length,3);
});
