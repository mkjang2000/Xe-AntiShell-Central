import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync(new URL("theme.js",import.meta.url),"utf8");
function setup(saved, denied=false){
  const listeners={},store={},meta={},root={dataset:{}},button={attrs:{},setAttribute(k,v){this.attrs[k]=v;},addEventListener(k,f){listeners[k]=f;}};
  const document={documentElement:root,querySelector:()=>meta,querySelectorAll:()=>[button],addEventListener:(name,fn)=>{if(name==="DOMContentLoaded")listeners.ready=fn;}};
  const localStorage={getItem(){if(denied)throw Error("denied");return saved;},setItem(k,v){if(denied)throw Error("denied");store[k]=v;}};
  vm.runInNewContext(source,{document,localStorage});return{root,button,meta,store,listeners};
}
test("central starts dark before DOM ready and persists explicit light selection",()=>{
 const x=setup(null);assert.equal(x.root.dataset.theme,"dark");assert.equal(x.meta.content,"#111820");x.listeners.ready();assert.equal(x.button.attrs["aria-pressed"],"true");x.listeners.click();assert.equal(x.root.dataset.theme,"light");assert.equal(x.store["xeas-central-theme"],"light");assert.equal(x.button.textContent,"다크 모드");
});
test("saved light wins while invalid values fall back to dark",()=>{assert.equal(setup("light").root.dataset.theme,"light");assert.equal(setup("invalid").root.dataset.theme,"dark");});
test("blocked browser storage does not prevent switching themes",()=>{const x=setup(null,true);x.listeners.ready();assert.doesNotThrow(()=>x.listeners.click());assert.equal(x.root.dataset.theme,"light");});
