/* Bassar Kàakpi - mini générateur de PDF, sans bibliothèque externe. Tout se passe dans le navigateur du visiteur. */
(function(g){
var W=595,H=842,M=48,CW=W-2*M;
var X={8364:128,8218:130,402:131,8222:132,8230:133,8224:134,8225:135,710:136,8240:137,352:138,8249:139,338:140,381:142,8216:145,8217:146,8220:147,8221:148,8226:149,8211:150,8212:151,732:152,8482:153,353:154,8250:155,339:156,382:158,376:159};
function enc(s){s=String(s==null?"":s).replace(/[\u2000-\u200B\u202F\u00A0]/g," ").replace(/\u2192/g,"->").replace(/\u2248/g,"~").replace(/[\u2605\u2713]/g,"*");var o="";for(var i=0;i<s.length;i++){var c=s.charCodeAt(i);if(c>=32&&c<127)o+=s.charAt(i);else if(c>=161&&c<256)o+=s.charAt(i);else if(X[c])o+=String.fromCharCode(X[c]);else if(c===10||c===13||c===9)o+=" ";else o+="?"}return o}
function pe(s){return enc(s).replace(/([\\()])/g,"\\$1")}
function wrap(t,max){var out=[];String(t==null?"":t).split(/\r?\n/).forEach(function(p){var line="";p.split(/\s+/).forEach(function(w){while(w.length>max){if(line){out.push(line);line=""}out.push(w.slice(0,max));w=w.slice(max)}if(!w)return;if((line?line.length+1:0)+w.length>max){out.push(line);line=w}else line=line?line+" "+w:w});out.push(line)});return out}
function build(o){
var pages=[],ops,y,imgs=o.images||[];
function np(){ops=[];pages.push(ops);y=H-M}
function txt(f,sz,x,yy,s,col){ops.push((col||"0.1 0.08 0.07")+" rg BT /"+f+" "+sz+" Tf "+x+" "+yy.toFixed(1)+" Td ("+pe(s)+") Tj ET")}
function rect(x,yy,w,h,col){ops.push(col+" rg "+x+" "+yy.toFixed(1)+" "+w+" "+h+" re f")}
np();rect(0,H-78,W,78,"0.28 0.15 0.10");txt("F2",20,M,H-40,"Bassar Kàakpi","1 1 1");txt("F1",10,M,H-58,"L'étoffe d'un peuple vivant","0.9 0.82 0.66");
y=H-110;txt("F2",16,M,y,o.title);y-=20;
(o.meta||[]).forEach(function(l){txt("F1",10,M,y,l,"0.35 0.3 0.28");y-=13});
(o.sections||[]).forEach(function(s){if(y<M+90)np();y-=10;rect(M,y-3,CW,1,"0.69 0.55 0.24");y-=17;txt("F2",12,M,y,s.h);y-=8;
s.rows.forEach(function(r){var lab=wrap(r[0],28),val=wrap(r[1]===""||r[1]==null?"-":r[1],60),n=Math.max(lab.length,val.length);if(y-n*14<M+30){np();y-=0}
y-=14;for(var i=0;i<n;i++){if(lab[i])txt("F2",10,M,y-i*14,lab[i],"0.35 0.3 0.28");if(val[i])txt("F1",10.5,M+175,y-i*14,val[i])}y-=(n-1)*14})});
if(imgs.length){if(y<M+170)np();y-=10;rect(M,y-3,CW,1,"0.69 0.55 0.24");y-=17;txt("F2",12,M,y,o.photosTitle||"Photos");y-=12;var x=M,rowH=0;
imgs.forEach(function(im,i){var w=Math.min(165,(CW-16)/3),h=w*im.h/im.w;if(i&&i%3===0){x=M;y-=rowH+10;rowH=0}if(y-h<M+30){np();y-=0;x=M;rowH=0}
ops.push("q "+w.toFixed(1)+" 0 0 "+h.toFixed(1)+" "+x.toFixed(1)+" "+(y-h).toFixed(1)+" cm /Im"+(i+1)+" Do Q");x+=w+8;rowH=Math.max(rowH,h)})}
pages.forEach(function(p,i){p.push("0.69 0.55 0.24 rg "+M+" 40 "+CW+" 0.8 re f");p.push("0.45 0.4 0.38 rg BT /F1 8 Tf "+M+" 28 Td ("+pe((o.footer||"")+"  -  "+(i+1)+"/"+pages.length)+") Tj ET")});
var objs=[];function add(s){objs.push(s);return objs.length}
add("<< /Type /Catalog /Pages 2 0 R >>");add(null);add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");
var ids=imgs.map(function(im){return add("<< /Type /XObject /Subtype /Image /Width "+im.w+" /Height "+im.h+" /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length "+im.bin.length+" >>\nstream\n"+im.bin+"\nendstream")});
var xo=ids.map(function(id,i){return "/Im"+(i+1)+" "+id+" 0 R"}).join(" "),res="<< /Font << /F1 3 0 R /F2 4 0 R >>"+(xo?" /XObject << "+xo+" >>":"")+" >>",kids=[];
pages.forEach(function(p){var st=p.join("\n"),cid=add("<< /Length "+st.length+" >>\nstream\n"+st+"\nendstream"),pid=add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 "+W+" "+H+"] /Resources "+res+" /Contents "+cid+" 0 R >>");kids.push(pid+" 0 R")});
objs[1]="<< /Type /Pages /Kids ["+kids.join(" ")+"] /Count "+kids.length+" >>";
var out="%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n",offs=[];objs.forEach(function(s,i){offs.push(out.length);out+=(i+1)+" 0 obj\n"+s+"\nendobj\n"});
var xr=out.length;out+="xref\n0 "+(objs.length+1)+"\n0000000000 65535 f \n"+offs.map(function(f){return("0000000000"+f).slice(-10)+" 00000 n \n"}).join("")+"trailer\n<< /Size "+(objs.length+1)+" /Root 1 0 R /Info << /Title ("+pe(o.title)+") /Producer (Bassar Kaakpi) >> >>\nstartxref\n"+xr+"\n%%EOF";return out}
function bytes(s){var a=new Uint8Array(s.length);for(var i=0;i<s.length;i++)a[i]=s.charCodeAt(i)&255;return a}
function toBlob(o){return new Blob([bytes(build(o))],{type:"application/pdf"})}
function photo(file){return new Promise(function(res,rej){var r=new FileReader();r.onload=function(){var im=new Image();im.onload=function(){var s=Math.min(1,900/Math.max(im.width,im.height)),w=Math.round(im.width*s),h=Math.round(im.height*s),c=document.createElement("canvas");c.width=w;c.height=h;var x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,w,h);x.drawImage(im,0,0,w,h);res({w:w,h:h,bin:atob(c.toDataURL("image/jpeg",.72).split(",")[1])})};im.onerror=rej;im.src=r.result};r.onerror=rej;r.readAsDataURL(file)})}
function deliver(blob,name,text){var f=null;try{f=new File([blob],name,{type:"application/pdf"})}catch(e){}
if(f&&navigator.canShare&&navigator.canShare({files:[f]}))return navigator.share({files:[f],title:name,text:text}).then(function(){return"shared"},function(e){return e&&e.name==="AbortError"?"cancel":"fallback"});return Promise.resolve("fallback")}
function download(blob,name){var a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();setTimeout(function(){a.remove()},800)}
g.BKPDF={build:build,toBlob:toBlob,photo:photo,deliver:deliver,download:download,bytes:bytes}})(typeof window!=="undefined"?window:globalThis);
