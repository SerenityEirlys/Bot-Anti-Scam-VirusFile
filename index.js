import 'dotenv/config'
import { Client, GatewayIntentBits, Partials, Events, REST, Routes, EmbedBuilder } from 'discord.js'
import express from 'express'
import { readdirSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs'
import crypto from 'crypto'
import path from 'path'
import { fileURLToPath, pathToFileURL } from 'url'

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ],
  partials: [Partials.Channel]
})
client.once(Events.ClientReady, async c => {
  console.log(`Logged in as ${c.user.tag}`)
  try {
    await c.application.fetch()
    const clientId = c.application.id
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN)
    const body = Array.from(commandDefinitions.values()).map(d => d)
    const cfg = readConfig()
    const guildId = process.env.GUILD_ID
    const inGuild = guildId && c.guilds.cache.has(guildId)
    if (inGuild || (cfg.guildIds && cfg.guildIds.length)) {
      try {
        try {
          await rest.put(Routes.applicationCommands(clientId), { body: [] })
          console.log('Cleared global commands to avoid duplicates')
        } catch (clearErr) {
          console.warn('Failed to clear global commands:', clearErr?.message || clearErr)
        }
        if (inGuild) {
          await rest.put(Routes.applicationGuildCommands(clientId, guildId), { body })
          console.log(`Registered ${body.length} commands to guild ${guildId}`)
        }
        await registerForGuilds(cfg, clientId, rest, body)
      } catch (e) {
        if (e?.status === 403 || e?.code === 50001) {
          console.warn('Guild register denied (403/50001). Falling back to global.')
          await rest.put(Routes.applicationCommands(clientId), { body })
          console.log(`Registered ${body.length} global commands`)
          const url = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&permissions=0&scope=bot%20applications.commands`
          console.warn(`Re-invite bot with commands scope if needed: ${url}`)
        } else {
          throw e
        }
      }
    } else {
      await rest.put(Routes.applicationCommands(clientId), { body })
      console.log(`Registered ${body.length} global commands`)
      if (guildId && !inGuild) {
        const url = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&permissions=0&scope=bot%20applications.commands`
        console.warn(`Bot is not in guild ${guildId}. Invite with: ${url}`)
      }
    }
  } catch (err) {
    console.error('Failed to register slash commands:', err)
  }
})
client.on(Events.GuildCreate, async g => {
  try {
    if (!client.isReady()) return
    await client.application.fetch()
    const clientId = client.application.id
    const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN)
    const body = Array.from(commandDefinitions.values()).map(d => d)
    await rest.put(Routes.applicationGuildCommands(clientId, g.id), { body })
    console.log(`Registered ${body.length} commands to joined guild ${g.id}`)
  } catch {}
})
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const commands = new Map()
const commandDefinitions = new Map()
const commandsDir = path.join(__dirname, 'commands')
try {
  const files = readdirSync(commandsDir).filter(f => f.endsWith('.js'))
  for (const file of files) {
    const filePath = path.join(commandsDir, file)
    const mod = await import(pathToFileURL(filePath).href)
    if (mod && mod.data && typeof mod.execute === 'function') {
      const name = typeof mod.data.name === 'string' ? mod.data.name : mod.data.name
      commands.set(name, mod.execute)
      commandDefinitions.set(name, typeof mod.data.toJSON === 'function' ? mod.data.toJSON() : mod.data)
    }
  }
} catch (err) {
  console.error('Failed to load commands:', err)
}
client.on(Events.InteractionCreate, async interaction => {
  if (!interaction.isChatInputCommand()) return
  const cmd = commands.get(interaction.commandName)
  if (!cmd) return
  await cmd(interaction)
})
async function vtSubmitUrl(u){
  const key=(readConfig().vtApiKey||'')||process.env.VT_API_KEY
  if(!key) return {malicious:false}
  const ctrl=new AbortController()
  const t=setTimeout(()=>ctrl.abort(),15000)
  try{
    console.log(`[VT] submit ${u}`)
    const r=await fetch('https://www.virustotal.com/api/v3/urls',{method:'POST',headers:{'x-apikey':key,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({url:u}).toString(),signal:ctrl.signal})
    if(!r.ok) return {malicious:false}
    const j=await r.json()
    const id=j?.data?.id
    if(!id) return {malicious:false}
    for(let i=0;i<6;i++){
      await new Promise(r=>setTimeout(r,1500))
      const ra=await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`,{headers:{'x-apikey':key},signal:ctrl.signal})
      if(!ra.ok) continue
      const ja=await ra.json()
      const st=ja?.data?.attributes?.status
      if(st!=='completed') continue
      const stats=ja?.data?.attributes?.stats||{}
      const malicious=(stats.malicious||0)>0||(stats.suspicious||0)>0
      console.log(`[VT] result for ${u} -> malicious:${malicious} stats:`, stats)
      return {malicious,stats}
    }
    return {malicious:false}
  }catch{return {malicious:false}} finally{clearTimeout(t)}
}

function extractUrls(msg){
  const urls=[]
  const rx=/(https?:\/\/[^\s]+)/gi
  const c=msg.content||''
  let m
  while((m=rx.exec(c))!==null){urls.push(m[0])}
  for (const att of msg.attachments.values()) { if(att?.url) urls.push(att.url) }
  return Array.from(new Set(urls))
}

async function downloadFile(u){
  const ctrl=new AbortController()
  const t=setTimeout(()=>ctrl.abort(),20000)
  try{
    const r=await fetch(u,{signal:ctrl.signal})
    if(!r.ok) return null
    const len=Number(r.headers.get('content-length')||0)
    if(len && len>26214400) return null
    const ab=await r.arrayBuffer()
    const buf=Buffer.from(ab)
    const sha256=crypto.createHash('sha256').update(buf).digest('hex')
    if(buf.length>26214400) return null
    let name='file'
    try{
      const uo=new URL(u)
      const p=uo.pathname.split('/').filter(Boolean)
      if(p.length) name=p[p.length-1]
    }catch{}
    return { buffer: buf, name, sha256 }
  }catch{return null} finally{clearTimeout(t)}
}

async function vtSubmitFile(fileBuf, filename){
  const key=(readConfig().vtApiKey||'')||process.env.VT_API_KEY
  if(!key) return {malicious:false}
  const ctrl=new AbortController()
  const t=setTimeout(()=>ctrl.abort(),30000)
  try{
    const sha256Local=crypto.createHash('sha256').update(fileBuf).digest('hex')
    const guiLink=`https://www.virustotal.com/gui/file/${sha256Local}`
    const fd=new FormData()
    const blob=new Blob([fileBuf])
    fd.append('file', blob, filename||'file')
    console.log(`[VT] upload file ${filename||'file'} (${fileBuf.length} bytes)`)
    const r=await fetch('https://www.virustotal.com/api/v3/files',{method:'POST',headers:{'x-apikey':key},body:fd,signal:ctrl.signal})
    if(!r.ok) return {malicious:false}
    const j=await r.json()
    const id=j?.data?.id
    if(!id) return {malicious:false}
    let sha256
    for(let i=0;i<10;i++){
      await new Promise(r=>setTimeout(r,2000))
      const ra=await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`,{headers:{'x-apikey':key},signal:ctrl.signal})
      if(!ra.ok) continue
      const ja=await ra.json()
      const st=ja?.data?.attributes?.status
      if(st!=='completed') continue
      const stats=ja?.data?.attributes?.stats||{}
      sha256=ja?.meta?.file_info?.sha256
      const malicious=(stats.malicious||0)>0||(stats.suspicious||0)>0
      const link=sha256?`https://www.virustotal.com/gui/file/${sha256}`:guiLink
      console.log(`[VT] file result malicious:${malicious} sha256:${sha256||sha256Local}`)
      return {malicious,stats,link}
    }
    return {malicious:false,link:guiLink}
  }catch{return {malicious:false}} finally{clearTimeout(t)}
}

const lastScanAt=new Map()
const fileScanCache=new Map()
const warnCounts=new Map()
const spamHistory=new Map()

function addWarn(guildId, userId){
  let g=warnCounts.get(guildId)
  if(!g){g=new Map();warnCounts.set(guildId,g)}
  const v=(g.get(userId)||0)+1
  g.set(userId,v)
  return v
}

async function enforceOnUser(msg, reason){
  const cfg=readConfig()
  const count=addWarn(msg.guild.id, msg.author.id)
  const act=cfg.antiscam.action
  const thr=cfg.antiscam.warnThreshold
  if(cfg.antiscam.deleteMessage){ try{ await msg.delete().catch(()=>{}) }catch{} }
  try{
    const embed=new EmbedBuilder().setColor(0xFF0000).setTitle('antiscam').setDescription(reason).addFields(
      { name: 'Người gửi', value: `${msg.author?.tag||msg.author?.id}`, inline: true },
      { name: 'Cảnh cáo', value: `${count}/${thr}`, inline: true }
    )
    await msg.channel.send({ embeds: [embed] }).catch(()=>{})
  }catch{}
  if(count>=thr){
    if(act==='kick'){
      try{ await msg.guild.members.kick(msg.author.id).catch(()=>{}) }catch{}
    } else if(act==='ban'){
      try{ await msg.guild.members.ban(msg.author.id,{reason:'antiscam'}).catch(()=>{}) }catch{}
    }
  }
}

function trackSpam(guildId, channelId, userId, now, windowMs){
  let g=spamHistory.get(guildId); if(!g){g=new Map(); spamHistory.set(guildId,g)}
  let c=g.get(channelId); if(!c){c=new Map(); g.set(channelId,c)}
  let arr=c.get(userId); if(!arr){arr=[]}
  arr.push(now)
  const cutoff=now-windowMs
  arr=arr.filter(t=>t>=cutoff)
  c.set(userId,arr)
  return arr.length
}
client.on(Events.MessageCreate, async msg => {
  try{
    if(msg.author?.bot) return
    if(!msg.guild) return
    const cfg=readConfig()
    if(!cfg.virusScan){
      return
    }
    if(!((readConfig().vtApiKey||'')||process.env.VT_API_KEY)){
      console.log('[VT] skipped: no API key configured')
      return
    }
    const now=Date.now()
    const last=lastScanAt.get(msg.channelId)||0
    if(now-last<2000) return
    lastScanAt.set(msg.channelId,now)
    const spamCfg=readConfig().antiscam.spam
    if(spamCfg.enabled){
      const count=trackSpam(msg.guild.id, msg.channelId, msg.author.id, now, spamCfg.windowSec*1000)
      if(count>spamCfg.maxMessages){
        if(spamCfg.deleteMessage){ try{ await msg.delete().catch(()=>{}) }catch{} }
        const warns=addWarn(msg.guild.id, msg.author.id)
        try{
          const embed=new EmbedBuilder().setColor(0xFF0000).setTitle('antiscam').setDescription('spam tin nhắn').addFields(
            { name: 'Người gửi', value: `${msg.author?.tag||msg.author?.id}`, inline: true },
            { name: 'Cảnh cáo', value: `${warns}/${spamCfg.warnThreshold}`, inline: true }
          )
          await msg.channel.send({ embeds: [embed] }).catch(()=>{})
        }catch{}
        if(warns>=spamCfg.warnThreshold){
          try{ await msg.member.timeout(spamCfg.muteMinutes*60*1000,'spam').catch(()=>{}) }catch{}
        }
        return
      }
    }
    const urls=extractUrls(msg)
    console.log(`[VT] message ${msg.id} by ${msg.author?.tag||msg.author?.id}: found ${urls.length} url(s) in #${msg.channel?.name||msg.channelId}`)
    if(urls.length===0) return
    const cfgAnt=readConfig().antiscam
    const isSuspiciousText=/(nitro|free|gift|crack|hack|cheat|virus|malware|roblox)/i.test(msg.content||'')
    const hasSuspiciousImage=[...msg.attachments.values()].some(a=>{
      const n=(a.name||'').toLowerCase()
      return (a.contentType||'').startsWith('image/')||/(\.png|\.jpg|\.jpeg|\.gif|\.webp)$/.test(n)
    })
    if(cfgAnt.imageScan && (isSuspiciousText && hasSuspiciousImage)){
      await enforceOnUser(msg, 'mã độc discord')
      return
    }
    for(const u of urls){
      const dl=await downloadFile(u)
      let res
      if(dl){
        const quickLink=`https://www.virustotal.com/gui/file/${dl.sha256}`
        try{
          const embed=new EmbedBuilder()
            .setColor(0xFF0000)
            .setTitle('antiscam')
            .setDescription(dl.name)
            .addFields(
              { name: 'Người gửi', value: `${msg.author?.tag||msg.author?.id}`, inline: true },
              { name: 'Loại', value: 'mã độc discord', inline: true },
              { name: 'VirusTotal', value: quickLink, inline: false }
            )
          await msg.reply({ embeds: [embed] }).catch(()=>{})
        }catch{}
        const cached=fileScanCache.get(dl.sha256)
        if(cached){
          if(cached.malicious){
            console.log(`[VT] cached malicious for ${dl.name} ${dl.sha256}, deleting and kicking`)
            await enforceOnUser(msg, 'mã độc discord')
            break
          } else {
            continue
          }
        }
        res=await vtSubmitFile(dl.buffer, dl.name)
        if(res?.link){
          console.log(`[VT] replied with file report link ${res.link}`)
          try{
            const embed2=new EmbedBuilder()
              .setColor(0xFF0000)
              .setTitle('antiscam')
              .setDescription(dl.name)
              .addFields(
                { name: 'Người gửi', value: `${msg.author?.tag||msg.author?.id}`, inline: true },
                { name: 'Loại', value: 'mã độc discord', inline: true },
                { name: 'VirusTotal', value: res.link, inline: false }
              )
            await msg.reply({ embeds: [embed2] }).catch(()=>{})
          }catch{}
        }
        fileScanCache.set(dl.sha256,{ malicious: !!res?.malicious, link: res?.link || quickLink, name: dl.name, at: Date.now() })
      } else {
        res=await vtSubmitUrl(u)
      }
      if(res.malicious){
        console.log(`[VT] malicious detected from user ${msg.author?.tag||msg.author?.id}`)
        await enforceOnUser(msg, 'mã độc discord')
        break
      }
    }
  }catch{}
})

const app = express()
app.use(express.static(path.join(__dirname, 'panel')))
app.use(express.json())
app.get('/api/status', (req, res) => {
  const ready = client.isReady()
  const userTag = ready ? client.user.tag : null
  const guildCount = ready ? client.guilds.cache.size : 0
  res.json({ ready, userTag, guildCount })
})
app.get('/api/guilds', (req, res) => {
  if (!client.isReady()) return res.json([])
  const data = client.guilds.cache.map(g => ({ id: g.id, name: g.name }))
  res.json(data)
})

const dataDir = path.join(__dirname, 'data')
const configPath = path.join(dataDir, 'config.json')
function ensureConfig() {
  if (!existsSync(dataDir)) mkdirSync(dataDir)
  if (!existsSync(configPath)) writeFileSync(configPath, JSON.stringify({ guildIds: [], virusScan: false, vtApiKey: '', antiscam: { imageScan: false, deleteMessage: true, warnThreshold: 3, action: 'kick', spam: { enabled: false, windowSec: 5, maxMessages: 5, deleteMessage: true, warnThreshold: 3, muteMinutes: 10 } } }, null, 2))
}
function readConfig() {
  ensureConfig()
  const cfg = JSON.parse(readFileSync(configPath, 'utf8'))
  if (!('virusScan' in cfg)) cfg.virusScan = false
  if (!Array.isArray(cfg.guildIds)) cfg.guildIds = []
  if (typeof cfg.vtApiKey !== 'string') cfg.vtApiKey = ''
  if (typeof cfg.antiscam !== 'object' || cfg.antiscam === null) cfg.antiscam = { imageScan: false, deleteMessage: true, warnThreshold: 3, action: 'kick', spam: { enabled: false, windowSec: 5, maxMessages: 5, deleteMessage: true, warnThreshold: 3, muteMinutes: 10 } }
  if (typeof cfg.antiscam.imageScan !== 'boolean') cfg.antiscam.imageScan = false
  if (typeof cfg.antiscam.deleteMessage !== 'boolean') cfg.antiscam.deleteMessage = true
  if (typeof cfg.antiscam.warnThreshold !== 'number') cfg.antiscam.warnThreshold = 3
  if (!['none','kick','ban','kick','ban'].includes(cfg.antiscam.action)) cfg.antiscam.action = 'kick'
  if (typeof cfg.antiscam.spam !== 'object' || cfg.antiscam.spam === null) cfg.antiscam.spam = { enabled: false, windowSec: 5, maxMessages: 5, deleteMessage: true, warnThreshold: 3, muteMinutes: 10 }
  if (typeof cfg.antiscam.spam.enabled !== 'boolean') cfg.antiscam.spam.enabled = false
  if (typeof cfg.antiscam.spam.windowSec !== 'number') cfg.antiscam.spam.windowSec = 5
  if (typeof cfg.antiscam.spam.maxMessages !== 'number') cfg.antiscam.spam.maxMessages = 5
  if (typeof cfg.antiscam.spam.deleteMessage !== 'boolean') cfg.antiscam.spam.deleteMessage = true
  if (typeof cfg.antiscam.spam.warnThreshold !== 'number') cfg.antiscam.spam.warnThreshold = 3
  if (typeof cfg.antiscam.spam.muteMinutes !== 'number') cfg.antiscam.spam.muteMinutes = 10
  return cfg
}
function writeConfig(cfg) {
  writeFileSync(configPath, JSON.stringify(cfg, null, 2))
}

app.get('/api/config', (req, res) => {
  const cfg = readConfig()
  res.json({ guildIds: cfg.guildIds, virusScan: cfg.virusScan, hasVtKey: !!cfg.vtApiKey, antiscam: cfg.antiscam })
})

app.post('/api/config', (req, res) => {
  const body = req.body || {}
  const cfg = readConfig()
  if (typeof body.virusScan === 'boolean') cfg.virusScan = body.virusScan
  if (typeof body.vtApiKey === 'string') cfg.vtApiKey = body.vtApiKey
  if (typeof body.antiscam === 'object' && body.antiscam){
    const a = body.antiscam
    if (typeof a.imageScan === 'boolean') cfg.antiscam.imageScan = a.imageScan
    if (typeof a.deleteMessage === 'boolean') cfg.antiscam.deleteMessage = a.deleteMessage
    if (typeof a.warnThreshold === 'number') cfg.antiscam.warnThreshold = Math.max(1, Math.floor(a.warnThreshold))
    if (typeof a.action === 'string' && ['none','kick','ban'].includes(a.action)) cfg.antiscam.action = a.action
    if (typeof a.spam === 'object' && a.spam){
      const s=a.spam
      if (typeof s.enabled === 'boolean') cfg.antiscam.spam.enabled = s.enabled
      if (typeof s.windowSec === 'number') cfg.antiscam.spam.windowSec = Math.max(1, Math.floor(s.windowSec))
      if (typeof s.maxMessages === 'number') cfg.antiscam.spam.maxMessages = Math.max(1, Math.floor(s.maxMessages))
      if (typeof s.deleteMessage === 'boolean') cfg.antiscam.spam.deleteMessage = s.deleteMessage
      if (typeof s.warnThreshold === 'number') cfg.antiscam.spam.warnThreshold = Math.max(1, Math.floor(s.warnThreshold))
      if (typeof s.muteMinutes === 'number') cfg.antiscam.spam.muteMinutes = Math.max(1, Math.floor(s.muteMinutes))
    }
  }
  writeConfig(cfg)
  res.json({ ok: true })
})

app.delete('/api/config/vt', (req, res) => {
  const cfg = readConfig()
  cfg.vtApiKey = ''
  writeConfig(cfg)
  res.json({ ok: true })
})

async function registerForGuilds(cfg, clientId, rest, body) {
  const ids = Array.isArray(cfg.guildIds) ? cfg.guildIds : []
  for (const id of ids) {
    if (!client.guilds.cache.has(id)) continue
    try {
      await rest.put(Routes.applicationGuildCommands(clientId, id), { body })
      console.log(`Registered ${body.length} commands to guild ${id}`)
    } catch (e) {
      console.warn(`Failed to register commands to guild ${id}:`, e?.message || e)
    }
  }
}

app.post('/api/guilds', async (req, res) => {
  const id = String(req.body?.id || '').trim()
  if (!/^[0-9]{6,}$/.test(id)) return res.status(400).json({ error: 'invalid id' })
  const cfg = readConfig()
  if (!cfg.guildIds.includes(id)) cfg.guildIds.push(id)
  writeConfig(cfg)
  try {
    if (client.isReady()) {
      await client.application.fetch()
      const clientId = client.application.id
      const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN)
      const body = Array.from(commandDefinitions.values()).map(d => d)
      await registerForGuilds(cfg, clientId, rest, body)
    }
  } catch {}
  res.json(cfg)
})

app.delete('/api/guilds/:id', async (req, res) => {
  const id = String(req.params.id)
  const cfg = readConfig()
  cfg.guildIds = cfg.guildIds.filter(x => x !== id)
  writeConfig(cfg)
  try {
    if (client.isReady()) {
      await client.application.fetch()
      const clientId = client.application.id
      const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN)
      await rest.put(Routes.applicationGuildCommands(clientId, id), { body: [] })
      console.log(`Cleared commands from guild ${id}`)
    }
  } catch {}
  res.json(cfg)
})
const port = Number(process.env.PORT || 3000)
app.listen(port, () => {
  console.log(`Panel at http://localhost:${port}`)
})

client.login(process.env.DISCORD_TOKEN)


