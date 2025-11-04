async function loadStatus(){
  const r=await fetch('/api/status');
  const s=await r.json();
  const el=document.getElementById('status');
  const badge=s.ready?'<span class="badge ok">Online</span>':'<span class="badge err">Offline</span>';
  el.innerHTML=`${badge}<div>${s.userTag||''}</div><div>${s.guildCount||0} servers</div>`
}
async function loadGuilds(){
  const [rg, rc]=await Promise.all([
    fetch('/api/guilds'),
    fetch('/api/config')
  ]);
  const g=await rg.json();
  const cfg=await rc.json();
  const ul=document.getElementById('guilds');
  const set=new Set(cfg.guildIds||[]);
  ul.innerHTML=g.map(x=>{
    const tracked=set.has(x.id)?'tracked':'not-tracked';
    return `<li>${x.name} <small style="opacity:.7">(${x.id})</small> <small>[${tracked}]</small> <button data-remove="${x.id}">Xóa</button></li>`
  }).join('') + (Array.from(set).filter(id=>!g.find(z=>z.id===id)).map(id=>`<li><small>(Chưa có trong servers)</small> <small style="opacity:.7">(${id})</small> <button data-remove="${id}">Xóa</button></li>`).join(''))
  ul.querySelectorAll('button[data-remove]').forEach(btn=>{
    btn.onclick=async()=>{
      const id=btn.getAttribute('data-remove');
      await fetch(`/api/guilds/${id}`,{method:'DELETE'});
      loadGuilds();
    }
  })
}
document.getElementById('addGuild').onclick=async()=>{
  const input=document.getElementById('guildInput');
  const id=(input.value||'').trim();
  if(!id) return;
  await fetch('/api/guilds',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  input.value='';
  loadGuilds();
}
loadStatus();
loadGuilds();
setInterval(loadStatus,5000);
setInterval(loadGuilds,5000);
document.querySelectorAll('.tab').forEach(t=>{
  t.onclick=()=>{
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'))
    document.querySelectorAll('.side').forEach(x=>x.classList.remove('active'))
    document.querySelectorAll('.tabpane').forEach(x=>x.classList.remove('active'))
    t.classList.add('active')
    const key=t.getAttribute('data-tab')
    const pane=document.getElementById(`tab-${key}`)
    const side=[...document.querySelectorAll('.side')].find(x=>x.getAttribute('data-tab-link')===key)
    if(side) side.classList.add('active')
    if(pane) pane.classList.add('active')
  }
})
document.querySelectorAll('[data-tab-link]').forEach(a=>{
  a.onclick=(e)=>{
    e.preventDefault()
    const key=a.getAttribute('data-tab-link')
    document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'))
    document.querySelectorAll('.side').forEach(x=>x.classList.remove('active'))
    document.querySelectorAll('.tabpane').forEach(x=>x.classList.remove('active'))
    a.classList.add('active')
    const pane=document.getElementById(`tab-${key}`)
    if(pane) pane.classList.add('active')
    const anchor=document.querySelector('.layout')||document.querySelector('.tabs')||document.body
    window.scrollTo({ top: anchor.getBoundingClientRect().top + window.scrollY - 10, behavior: 'smooth' })
  }
})
async function loadToggle(){
  const r=await fetch('/api/config');
  const cfg=await r.json();
  const cb=document.getElementById('virusToggle');
  if(cb){cb.checked=!!cfg.virusScan;cb.onchange=async()=>{
    await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({virusScan:cb.checked})});
  }}
  const vt=document.getElementById('vtStatus');
  if(vt) vt.textContent=cfg.hasVtKey?'API Key: đã thiết lập':'API Key: chưa thiết lập';
  const keyInput=document.getElementById('vtKey');
  if(keyInput) keyInput.value='';
  const as=cfg.antiscam||{};
  const asImage=document.getElementById('asImage');
  const asDelete=document.getElementById('asDelete');
  const asThreshold=document.getElementById('asThreshold');
  const asAction=document.getElementById('asAction');
  if(asImage) asImage.checked=!!as.imageScan;
  if(asDelete) asDelete.checked=!!as.deleteMessage;
  if(asThreshold) asThreshold.value=as.warnThreshold||3;
  if(asAction) asAction.value=as.action||'kick';
  const sp=as.spam||{};
  const spamEnabled=document.getElementById('spamEnabled');
  const spamWindow=document.getElementById('spamWindow');
  const spamMax=document.getElementById('spamMax');
  const spamWarn=document.getElementById('spamWarn');
  const spamMute=document.getElementById('spamMute');
  if(spamEnabled) spamEnabled.checked=!!sp.enabled;
  if(spamWindow) spamWindow.value=sp.windowSec||5;
  if(spamMax) spamMax.value=sp.maxMessages||5;
  if(spamWarn) spamWarn.value=sp.warnThreshold||3;
  if(spamMute) spamMute.value=sp.muteMinutes||10;
}
loadToggle();
setInterval(loadToggle,5000);

document.getElementById('saveVt').onclick=async()=>{
  const key=(document.getElementById('vtKey').value||'').trim();
  if(!key) return;
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vtApiKey:key})});
  document.getElementById('vtKey').value='';
  loadToggle();
}
document.getElementById('clearVt').onclick=async()=>{
  await fetch('/api/config/vt',{method:'DELETE'});
  loadToggle();
}
document.getElementById('saveAS').onclick=async()=>{
  const body={
    antiscam:{
      imageScan: document.getElementById('asImage').checked,
      deleteMessage: document.getElementById('asDelete').checked,
      warnThreshold: Number(document.getElementById('asThreshold').value||3),
      action: document.getElementById('asAction').value,
      spam:{
        enabled: document.getElementById('spamEnabled').checked,
        windowSec: Number(document.getElementById('spamWindow').value||5),
        maxMessages: Number(document.getElementById('spamMax').value||5),
        warnThreshold: Number(document.getElementById('spamWarn').value||3),
        muteMinutes: Number(document.getElementById('spamMute').value||10),
        deleteMessage: true
      }
    }
  }
  await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  loadToggle();
}
