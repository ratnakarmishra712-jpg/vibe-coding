#pragma once
// The remote-control page served to your phone.
const char kPage[] PROGMEM = R"HTML(<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AC Remote</title>
<style>
:root{--bg:#eef1f4;--card:#fff;--ink:#1d2330;--mute:#6b7383;--acc:#2d7ff9;--on:#20b26b;--off:#d9dde3}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1d222b;--ink:#e8ebf0;--mute:#8a93a3;--off:#2c323d}}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--bg);color:var(--ink);font:16px system-ui,sans-serif;display:flex;justify-content:center}
.remote{width:100%;max-width:380px;margin:16px;padding:20px;background:var(--card);border-radius:28px;box-shadow:0 8px 30px #0002}
.screen{background:#0f1a24;color:#9fe3ff;border-radius:16px;padding:16px;text-align:center;font-variant-numeric:tabular-nums}
.screen .t{font-size:64px;font-weight:300;line-height:1}
.screen .s{font-size:13px;letter-spacing:.08em;text-transform:uppercase;opacity:.8;margin-top:6px}
.screen.off{color:#3b4a57}
button{font:inherit;border:0;border-radius:14px;padding:14px 0;background:var(--off);color:var(--ink);cursor:pointer;width:100%}
button:active{transform:scale(.97)}
button.sel{background:var(--acc);color:#fff}
.power{background:#e5484d;color:#fff;font-weight:600;margin:16px 0}
.power.on{background:var(--on)}
.row{display:grid;gap:8px;margin-top:10px}
.r2{grid-template-columns:1fr 1fr}.r4{grid-template-columns:repeat(4,1fr)}.r5{grid-template-columns:repeat(5,1fr)}
.temp button{font-size:28px;font-weight:300}
label{display:block;font-size:12px;color:var(--mute);text-transform:uppercase;letter-spacing:.06em;margin-top:16px}
select{width:100%;padding:12px;border-radius:12px;border:1px solid var(--off);background:var(--card);color:var(--ink);font:inherit;margin-top:6px}
.msg{min-height:20px;font-size:13px;color:var(--mute);text-align:center;margin-top:12px}
small{color:var(--mute);font-size:12px;display:block;margin-top:6px;line-height:1.4}
</style></head><body>
<div class="remote">
  <div class="screen" id="screen"><div class="t" id="temp">24°</div><div class="s" id="status">Cool · Fan auto</div></div>
  <button class="power" id="power">Power</button>
  <div class="row r2 temp"><button id="down">−</button><button id="up">+</button></div>
  <label>Mode</label>
  <div class="row r5" id="modes"></div>
  <label>Fan</label>
  <div class="row r4" id="fans"></div>
  <div class="row r2" style="margin-top:16px">
    <button id="swing">Swing</button><button id="turbo">Turbo</button>
  </div>
  <label>AC brand / protocol</label>
  <select id="brand"></select>
  <small>Don't know the protocol? Pick one that matches your brand, set Cool 24°, and press Power. If nothing beeps, try the next one. <b>Model</b> matters for some brands (e.g. Gree, Mitsubishi).</small>
  <label>Model</label>
  <select id="model"><option value="-1">Default</option><option>1</option><option>2</option><option>3</option><option>4</option><option>5</option><option>6</option></select>
  <div class="msg" id="msg"></div>
</div>
<script>
const $=id=>document.getElementById(id);
const MODES=["cool","heat","dry","fan","auto"],FANS=["auto","low","medium","high"];
let s={power:false,mode:"cool",temp:24,fan:"auto",swing:false,turbo:false,brand:"",model:"-1"};
try{Object.assign(s,JSON.parse(localStorage.getItem("ac")||"{}"))}catch(e){}
const save=()=>{try{localStorage.setItem("ac",JSON.stringify(s))}catch(e){}};
function chips(el,list,key){list.forEach(v=>{const b=document.createElement("button");b.textContent=v[0].toUpperCase()+v.slice(1);b.dataset.v=v;b.onclick=()=>{s[key]=v;send()};$(el).appendChild(b)})}
chips("modes",MODES,"mode");chips("fans",FANS,"fan");
function render(){
  $("temp").textContent=s.power?s.temp+"°":"OFF";
  $("status").textContent=s.power?`${s.mode} · fan ${s.fan}${s.swing?" · swing":""}${s.turbo?" · turbo":""}`:"Standby";
  $("screen").classList.toggle("off",!s.power);
  $("power").classList.toggle("on",s.power);$("power").textContent=s.power?"Power: ON":"Power: OFF";
  document.querySelectorAll("#modes button").forEach(b=>b.classList.toggle("sel",b.dataset.v==s.mode));
  document.querySelectorAll("#fans button").forEach(b=>b.classList.toggle("sel",b.dataset.v==s.fan));
  $("swing").classList.toggle("sel",s.swing);$("turbo").classList.toggle("sel",s.turbo);
  $("model").value=s.model;
}
async function send(){
  render();save();
  if(!s.brand){$("msg").textContent="Pick your AC brand first";return}
  const q=new URLSearchParams({brand:s.brand,model:s.model,power:s.power?1:0,mode:s.mode,temp:s.temp,fan:s.fan,swing:s.swing?1:0,turbo:s.turbo?1:0});
  $("msg").textContent="Sending…";
  try{const r=await fetch("/send?"+q);$("msg").textContent=r.ok?"Sent ✓":await r.text()}
  catch(e){$("msg").textContent="Can't reach the remote — are you on its Wi-Fi?"}
}
$("power").onclick=()=>{s.power=!s.power;send()};
$("up").onclick=()=>{s.temp=Math.min(30,s.temp+1);send()};
$("down").onclick=()=>{s.temp=Math.max(16,s.temp-1);send()};
$("swing").onclick=()=>{s.swing=!s.swing;send()};
$("turbo").onclick=()=>{s.turbo=!s.turbo;send()};
$("brand").onchange=e=>{s.brand=e.target.value;save();$("msg").textContent="Brand set — press Power to test"};
$("model").onchange=e=>{s.model=e.target.value;save()};
fetch("/protocols").then(r=>r.json()).then(list=>{
  $("brand").innerHTML='<option value="">— choose —</option>'+list.sort().map(p=>`<option>${p}</option>`).join("");
  $("brand").value=s.brand;
}).catch(()=>{$("msg").textContent="Can't reach the remote"});
render();
</script></body></html>)HTML";
