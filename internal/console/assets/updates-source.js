"use strict";

// Only public, strictly shaped publisher metadata can enter an upload header.
// Cryptographic publisher verification remains mandatory on central and agent.
(function (C) {
  const invalid="서명된 공개 manifest JSON만 선택하세요. 개인키·알 수 없는 필드·잘못된 형식은 전송하지 않습니다.";
  const failure=()=>new Error(invalid);
  const exact=(value,keys)=>value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.hasOwn(value,key));
  const component=value=>typeof value==="string"&&/^[A-Za-z0-9][A-Za-z0-9._+~^]{0,127}$/.test(value);
  const admin=()=>{if(C.session?.role!=="admin")throw new Error("릴리즈 등록·가져오기·삭제는 관리자만 할 수 있습니다.");};
  const rejectDuplicateKeys=text=>{
    const objects=[];
    for(let index=0;index<text.length;index++){
      const char=text[index];
      if(char==="{"||char==="["){objects.push(char==="{"?new Set():null);if(objects.length>16)throw failure();}
      else if(char==="}"||char==="]")objects.pop();
      else if(char==='"'){
        const start=index++;
        for(;index<text.length;index++){if(text[index]==="\\"){index++;continue;}if(text[index]==='"')break;}
        let next=index+1;while(/\s/.test(text[next]||"")&&next<text.length)next++;
        if(text[next]===":"&&objects.at(-1)){const key=JSON.parse(text.slice(start,index+1)),keys=objects.at(-1);if(keys.has(key))throw failure();keys.add(key);}
      }
    }
  };
  C.releaseManifestHeader=async(file,expectedSize)=>{
    try{
      if(!file||!Number.isInteger(file.size)||file.size<1||file.size>16384||typeof file.arrayBuffer!=="function")throw failure();
      const bytes=new Uint8Array(await file.arrayBuffer());if(bytes.length!==file.size)throw failure();
      const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
      if(/-----BEGIN|private[_-]?key/i.test(text))throw failure();
      const value=JSON.parse(text);rejectDuplicateKeys(text);
      if(!exact(value,["manifest","key_id","signature"])||typeof value.key_id!=="string"||!/^[A-Za-z0-9._:-]{1,128}$/.test(value.key_id)||typeof value.signature!=="string"||!/^[A-Za-z0-9_-]{85}[AQgw]$/.test(value.signature))throw failure();
      const m=value.manifest;
      if(!exact(m,["schema_version","artifact_name","package","os_family","os_major","sha256","size","published_at"])||m.schema_version!=="1"||typeof m.artifact_name!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,220}\.rpm$/.test(m.artifact_name)||m.os_family!=="rhel"||!["7","8","9","10"].includes(m.os_major)||typeof m.sha256!=="string"||!/^[0-9a-f]{64}$/.test(m.sha256)||!Number.isInteger(m.size)||m.size<1||m.size>64*1024*1024||m.size!==expectedSize||typeof m.published_at!=="string"||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(m.published_at)||!Number.isFinite(Date.parse(m.published_at)))throw failure();
      const pkg=m.package,platform=typeof pkg?.release==="string"?/(?:^|\.)el(7|8|9|10)(?:[._]|$)/.exec(pkg.release):null;
      if(!exact(pkg,["name","epoch","version","release","arch"])||pkg.name!=="xe-antishell"||!Number.isInteger(pkg.epoch)||pkg.epoch<0||pkg.epoch>4294967295||!component(pkg.version)||!component(pkg.release)||pkg.arch!=="x86_64"||!platform||platform[1]!==m.os_major)throw failure();
      const publicBytes=new TextEncoder().encode(JSON.stringify(value));if(publicBytes.length>16384)throw failure();
      return btoa(String.fromCharCode(...publicBytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    }catch(_){throw failure();}
  };
  const transfer=(path,body,contentType,extraHeaders,onProgress,onStart,aborted)=>new Promise((resolve,reject)=>{
    if(aborted())return reject(new Error("전송을 중단했습니다. 등록 목록을 확인하세요."));
    admin();const xhr=new XMLHttpRequest();xhr.open("POST",path);xhr.timeout=300000;xhr.withCredentials=true;
    for(const [name,value] of Object.entries({Accept:"application/json","Content-Type":contentType,"X-CSRF-Token":C.session?.csrf_token||"",...extraHeaders}))xhr.setRequestHeader(name,value);
    xhr.upload.addEventListener("progress",event=>{if(event.lengthComputable)onProgress(Math.min(100,Math.round(event.loaded/event.total*100)));});
    xhr.addEventListener("load",()=>{
      let result;try{result=C.object(JSON.parse(xhr.responseText));}catch(_){reject(new Error("등록 응답 형식을 확인할 수 없습니다. 릴리즈 목록을 다시 확인하세요."));return;}
      if(xhr.status===200||xhr.status===201){if(!C.object(result.release).id||!C.object(result.release).sha256||result.release.publisher_verified!==true){reject(new Error("발행자 서명 검증 결과를 확인할 수 없습니다. 릴리즈 목록을 다시 확인하세요."));return;}resolve(result);return;}
      if(xhr.status===401)globalThis.location.assign("/login");const error=new Error(C.object(result).error||"릴리즈 서명·파일 검증 또는 등록을 완료하지 못했습니다.");error.status=xhr.status;reject(error);
    });
    for(const name of ["error","timeout","abort"])xhr.addEventListener(name,()=>reject(new Error(name==="timeout"?"전송 시간이 초과됐습니다. 서버에 등록됐는지 목록을 확인하세요.":name==="abort"?"전송을 중단했습니다. 서버에 등록됐는지 목록을 확인하세요.":"전송 연결이 끊겼습니다. 등록 목록을 확인한 뒤 다시 시도하세요.")));
    onStart(xhr);xhr.send(body);
  });
  C.uploadRPM=(file,manifest,onProgress=()=>{},onStart=()=>{})=>new Promise((resolve,reject)=>{
    try{admin();if(!file||!Number.isInteger(file.size)||file.size<1||file.size>64*1024*1024)throw new Error("1바이트 이상 64 MiB 이하의 에이전트 RPM을 선택하세요.");}catch(error){reject(error);return;}
    let child=null,aborted=false;onStart({abort(){aborted=true;child?.abort();}});
    C.releaseManifestHeader(manifest,file.size).then(header=>transfer("/api/updates/releases",file,"application/x-rpm",{"X-XEAS-Release-Manifest":header},onProgress,xhr=>{child=xhr;},()=>aborted)).then(resolve,reject);
  });
  C.importGithubRelease=(tag,asset,onStart=()=>{})=>{
    try{admin();if(typeof tag!=="string"||tag.length<1||tag.length>128||/[\x00-\x20\x7f]/.test(tag)||typeof asset!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,240}\.json$/.test(asset))throw new Error("GitHub 릴리즈와 공개 서명 manifest를 선택하세요.");}catch(error){return Promise.reject(error);}
    return transfer("/api/updates/github/import",JSON.stringify({tag,manifest_asset:asset}),"application/json",{},()=>{},onStart,()=>false);
  };
})(globalThis.XEC);
