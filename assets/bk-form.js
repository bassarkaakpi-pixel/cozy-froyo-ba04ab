/* Bassar Kàakpi - moteur de formulaire (trois langues) qui produit un PDF à envoyer sur WhatsApp */
(function(g){
var PHONE="+49 177 2075847",WA="491772075847";
function $(t,c,h){var e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e}
function init(cfg){
var root=document.getElementById(cfg.mount),L=function(){return window.curLang||"en"},tt=function(k,l){l=l||L();var a=cfg.t[l]&&cfg.t[l][k];if(a!=null)return a;var b=cfg.common[l][k];return b!=null?b:k};
var els={},labs=[],form=$("form","bkf"),photos=[],state=null,sub=$("div","req"),btn=$("button","btn"),res=$("div","res");res.hidden=true;btn.type="submit";
cfg.fields.forEach(function(f){var w=$("div","fld"+(f.type==="checkbox"?" chk":"")),lab=$("label"),inp;lab.htmlFor="f-"+f.id;
if(f.type==="select")inp=$("select");else if(f.type==="textarea"){inp=$("textarea");inp.rows=f.rows||4}else{inp=$("input");inp.type=f.type}
inp.id="f-"+f.id;inp.name=f.id;if(f.max)inp.maxLength=f.max;if(f.type==="number"){inp.min=0;inp.setAttribute("inputmode","numeric")}if(f.type==="file"){inp.accept="image/*";inp.multiple=true}
if(f.type==="checkbox"){w.appendChild(inp);w.appendChild(lab)}else{w.appendChild(lab);w.appendChild(inp)}
if(f.type==="file"){var pv=$("div","thumbs2");w.appendChild(pv);f.pv=pv;inp.addEventListener("change",function(){var a=[].slice.call(inp.files);if(a.length>3){alert(tt("maxPhotos"));a=a.slice(0,3)}photos=a;pv.innerHTML="";a.forEach(function(x){var im=$("img");im.alt="";im.src=URL.createObjectURL(x);pv.appendChild(im)})})}
els[f.id]=inp;f.w=w;labs.push([f,lab,inp]);form.appendChild(w);inp.addEventListener("change",refresh)});
form.appendChild(sub);form.appendChild(btn);root.appendChild(form);root.appendChild(res);
function refresh(){cfg.fields.forEach(function(f){var show=!f.showIf||f.showIf.in.indexOf(els[f.showIf.id].value)>-1;f.w.hidden=!show;els[f.id].required=!!f.req&&show});if(cfg.onUpdate)cfg.onUpdate(els,L(),tt)}
function labels(){labs.forEach(function(x){var f=x[0],lab=x[1],inp=x[2];lab.textContent=tt(f.k)+(f.req&&f.type!=="checkbox"?" *":"");if(f.ph)inp.placeholder=tt(f.ph);
if(f.type==="select"){var cur=inp.value;inp.innerHTML="";f.opts.forEach(function(o){var op=$("option");op.value=o.v;op.textContent=tt(o.k);inp.appendChild(op)});inp.value=cur||(f.opts[0]&&f.opts[0].v)||""}
if(f.type==="checkbox"&&f.req)lab.textContent=tt(f.k)+" *"});
sub.textContent=tt("req");btn.textContent=tt("create");var h=document.getElementById("ft"),i=document.getElementById("fi"),b=document.getElementById("back");if(h)h.textContent=tt("h1");if(i)i.textContent=tt("intro");if(b)b.textContent=tt("bk");document.title=tt("pageTitle")+" – Bassar Kàakpi";refresh();if(state)showRes()}
if(cfg.defaults)Object.keys(cfg.defaults).forEach(function(k){if(cfg.defaults[k])setTimeout(function(){els[k].value=cfg.defaults[k];refresh()},0)});
function fr(k){return tt(k,"fr")}
form.addEventListener("submit",function(ev){ev.preventDefault();if(!form.reportValidity())return;var v={};cfg.fields.forEach(function(f){var e=els[f.id];v[f.id]=f.type==="checkbox"?(!f.w.hidden&&e.checked):f.type==="file"?photos:(f.w.hidden?"":e.value.trim())});
btn.disabled=true;Promise.all(photos.map(BKPDF.photo)).then(function(imgs){var s=cfg.spec(v,imgs,fr);s.pdf.images=imgs;s.blob=BKPDF.toBlob(s.pdf);state=s;showRes()}).catch(function(){alert(tt("err"))}).then(function(){btn.disabled=false})});
function showRes(){var s=state;form.hidden=true;res.hidden=false;res.innerHTML="";var url=URL.createObjectURL(s.blob);
res.appendChild($("h2",null,tt("resT")));var p=$("p",null,tt("how").replace("{n}","<b>"+PHONE+"</b>"));res.appendChild(p);var a=$("div","acts"),msg=$("p","note");
var send=$("button","btn gold");send.type="button";send.textContent=tt("send");send.onclick=function(){BKPDF.deliver(s.blob,s.filename,s.summary).then(function(r){if(r==="shared")msg.textContent=tt("ok");else if(r==="fallback"){BKPDF.download(s.blob,s.filename);msg.textContent=tt("fb")}})};
var w=$("a","btn");w.target="_blank";w.rel="noopener";w.textContent=tt("wa");w.href="https://wa.me/"+WA+"?text="+encodeURIComponent(s.summary);
var d=$("button","btn ghost");d.type="button";d.textContent=tt("dl");d.onclick=function(){BKPDF.download(s.blob,s.filename)};
var vw=$("a","btn ghost");vw.target="_blank";vw.rel="noopener";vw.href=url;vw.textContent=tt("view");
var bk=$("button","btn ghost");bk.type="button";bk.textContent=tt("back2");bk.onclick=function(){res.hidden=true;form.hidden=false;state=null};
[send,w,d,vw,bk].forEach(function(x){a.appendChild(x)});res.appendChild(a);res.appendChild(msg)}
document.addEventListener("langchange",labels);labels()}
g.BKForm={init:init}})(window);
