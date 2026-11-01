/* Kör: node tests/summary-device.test.js  (kräver playwright, använder demoläget) */
const {chromium}=require('playwright');const path=require('path');const assert=require('assert');
(async()=>{const b=await chromium.launch(),p=await b.newPage(),errs=[];p.on('pageerror',e=>errs.push(e.message));
await p.goto('file://'+path.resolve(__dirname,'../index.html'));await p.waitForTimeout(1500);
const r=await p.evaluate(()=>{
  const I=cfg.ids,all=Object.values(state.devices),pair=[state.devices[I.tvm],state.devices[I.tkt]];
  const cn=consumersNow();
  return {
    hasSummary:!!state.devices[I.tvtork],
    summaryHidden:!propDevices().some(d=>d.id===I.tvtork),
    pairKept:pair.every(d=>propDevices().some(x=>x.id===d.id)),
    pairW:sumPower(pair),pairKwh:sumEnergy(pair),
    withSummaryW:sumPower([...pair,state.devices[I.tvtork]]),withSummaryKwh:sumEnergy([...pair,state.devices[I.tvtork]]),
    allW:sumPower(all.filter(d=>d.id===I.tvm||d.id===I.tkt||d.id===I.tvtork)),
    consumers:cn.on.filter(x=>[I.tvm,I.tkt,I.tvtork].includes(x.d.id)).map(x=>[x.d.id,x.w]),
    extraHasSummary:EXTRA_SERIES().some(x=>x[1]===I.tvtork),
    ids:I};});
assert(r.hasSummary,'demo ska ha den virtuella enheten');
assert(r.summaryHidden,'virtuell enhet ska inte ingå i propDevices');
assert(r.pairKept,'tvättmaskin och torktumlare ska finnas kvar');
assert.strictEqual(Math.round(r.pairW*100)/100,1026.72);
assert.strictEqual(Math.round(r.pairKwh*1000)/1000,37.855);
assert.strictEqual(r.withSummaryW,r.pairW,'virtuell enhet får inte tillföra effekt');
assert.strictEqual(r.withSummaryKwh,r.pairKwh,'virtuell enhet får inte tillföra energi');
assert.strictEqual(r.allW,r.pairW);
assert.deepStrictEqual(r.consumers.map(x=>x[0]).sort(),[r.ids.tvm,r.ids.tkt].sort(),'varje fysisk enhet exakt en gång, aldrig den virtuella');
assert(!r.extraHasSummary,'ingen historikserie för den virtuella enheten');
assert.deepStrictEqual(errs,[]);
console.log('OK: alla tester gick igenom');await b.close();})().catch(e=>{console.error('FEL:',e.message);process.exit(1);});
