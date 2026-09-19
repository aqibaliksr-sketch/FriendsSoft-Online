require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');
const { WebSocketServer } = require('ws');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 8080);
const SECRET = String(process.env.SESSION_SECRET || 'CHANGE_ME');
const DEV_KEY = String(process.env.DEVELOPER_KEY || 'CHANGE_ME');
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || 'true') !== 'false';
const STORES = ['students','teachers','batches','fees','attendance','teacherAttendance','expenses','settings','activity','customFields','courses','tests','results','timetable','salaries','salaryLedger','users','admissionEnquiries'];
const pool = new Pool({host:process.env.DB_HOST||'127.0.0.1',port:Number(process.env.DB_PORT||5432),user:process.env.DB_USER||'friendssoft',password:process.env.DB_PASSWORD||'',database:process.env.DB_NAME||'friendssoft',max:20,ssl: process.env.DB_SSL === 'false' ? false : {rejectUnauthorized:false}});
function pgSql(sql){ let i=0; return sql.replace(/\?/g,()=>'$'+(++i)); }
async function query(sql, params=[]){ return query(pgSql(sql), params); }

const app = express();
app.use(cookieParser());
app.get('/health',(req,res)=>res.json({status:true,service:'FriendsSoft Cloud',time:new Date().toISOString()}));
app.use(express.json({limit:'500mb'}));
app.use(express.urlencoded({extended:true,limit:'500mb'}));
app.use((req,res,next)=>{res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');res.setHeader('Access-Control-Allow-Credentials','true');res.setHeader('Access-Control-Allow-Headers','Content-Type,X-Developer-Key');res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,OPTIONS');if(req.method==='OPTIONS')return res.sendStatus(204);next();});

function b64(v){return Buffer.from(v).toString('base64url');}
function sign(payload){const p=b64(JSON.stringify(payload));const s=crypto.createHmac('sha256',SECRET).update(p).digest('base64url');return p+'.'+s;}
function verify(token){try{const [p,s]=String(token||'').split('.');if(!p||!s)return null;const exp=crypto.createHmac('sha256',SECRET).update(p).digest('base64url');if(!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(exp)))return null;const x=JSON.parse(Buffer.from(p,'base64url').toString('utf8'));if(x.exp && Date.now()>x.exp)return null;return x;}catch(_){return null;}}
function setSession(res,school){const token=sign({sid:Number(school.id),code:school.code,name:school.name,exp:Date.now()+7*24*3600*1000});res.cookie('friendssoft_session',token,{httpOnly:true,sameSite:'lax',secure:COOKIE_SECURE,path:'/',maxAge:7*24*3600*1000});}
function getSession(req){const m=String(req.headers.cookie||'').match(/(?:^|;\s*)friendssoft_session=([^;]+)/);return verify(m&&m[1]);}
async function schoolById(id){const r=await query('SELECT * FROM schools WHERE id=? LIMIT 1',[id]);return r.rows[0]||null;}
async function schoolByLogin(login){const r=await query('SELECT * FROM schools WHERE username=? OR code=? LIMIT 1',[login,login]);return r.rows[0]||null;}
function hashPassword(p){return crypto.scryptSync(String(p),SECRET.slice(0,32),32).toString('hex');}
function checkPassword(p,h){try{return crypto.timingSafeEqual(Buffer.from(hashPassword(p),'hex'),Buffer.from(h,'hex'));}catch(_){return false;}}
function auth(req,res,next){const s=getSession(req);if(!s)return res.status(401).json({status:false,message:'Login required'});req.schoolId=s.sid;req.session=s;next();}
async function ensureActive(req,res,next){const s=await schoolById(req.schoolId);if(!s)return res.status(401).json({status:false,message:'School not found'});if(!s.active)return res.status(403).json({status:false,message:'School account disabled'});if(s.expiry_date && new Date().toISOString().slice(0,10)>String(s.expiry_date).slice(0,10))return res.status(403).json({status:false,expired:true,expiryDate:String(s.expiry_date).slice(0,10),message:'Software expired. Contact Developer.'});req.school=s;next();}
function dev(req,res,next){if(String(req.get('X-Developer-Key')||'')!==DEV_KEY)return res.status(403).json({status:false,message:'Developer authorization required'});next();}
function emptyStores(){const o={};for(const s of STORES)o[s]=[];return o;}
async function getStore(sid,store){const r=await query('SELECT data_json FROM school_data WHERE school_id=? AND store_name=?',[sid,store]);if(!r.rows[0])return [];try{const x=JSON.parse(r.rows[0].data_json);return Array.isArray(x)?x:[];}catch(_){return [];}}
async function saveStore(sid,store,rows){await query('INSERT INTO school_data(school_id,store_name,data_json) VALUES(?,?,?) ON CONFLICT (school_id, store_name) DO UPDATE SET data_json=EXCLUDED.data_json, updated_at=CURRENT_TIMESTAMP',[sid,store,JSON.stringify(Array.isArray(rows)?rows:[])]);}
async function getSnapshot(sid,includeActivity=false){const out=emptyStores();for(const s of STORES){if(s==='activity'&&!includeActivity)continue;out[s]=await getStore(sid,s);}return out;}
async function getDeletions(sid){const r=await query('SELECT deletion_key,deleted_at FROM school_deletions WHERE school_id=?',[sid]);const o={};for(const x of r.rows)o[x.deletion_key]=x.deleted_at;return o;}
async function countStores(sid){const o={};for(const s of STORES){if(s==='activity'){const r=await query('SELECT COUNT(*) c FROM activity_log WHERE school_id=? AND created_at::date=CURRENT_DATE',[sid]);o[s]=Number(r.rows[0].c);continue;}const rows=await getStore(sid,s);o[s]=rows.length;}return o;}

app.get('/',(req,res)=>{if(getSession(req))return res.redirect('/app');res.sendFile(path.join(__dirname,'login.html'));});
app.get('/login.html',(req,res)=>res.sendFile(path.join(__dirname,'login.html')));
app.post('/api/login',async(req,res)=>{try{const login=String(req.body.login||'').trim(),password=String(req.body.password||'');if(!login||!password)return res.status(400).json({status:false,message:'Username and password required'});const s=await schoolByLogin(login);if(!s||!checkPassword(password,s.password_hash))return res.status(401).json({status:false,message:'Invalid username or password'});if(!s.active)return res.status(403).json({status:false,message:'School account disabled'});if(s.expiry_date&&new Date().toISOString().slice(0,10)>String(s.expiry_date).slice(0,10))return res.status(403).json({status:false,expired:true,expiryDate:String(s.expiry_date).slice(0,10),message:'Software expired. Contact Developer.'});setSession(res,s);res.json({status:true,school:{id:s.id,code:s.code,name:s.name,expiryDate:s.expiry_date}});}catch(e){res.status(500).json({status:false,message:e.message});}});
app.post('/api/logout',(req,res)=>{res.cookie('friendssoft_session','',{httpOnly:true,sameSite:'lax',secure:COOKIE_SECURE,path:'/',maxAge:0});res.json({status:true});});
app.get('/api/me',auth,async(req,res)=>{const s=await schoolById(req.schoolId);res.json({status:true,school:{id:s.id,code:s.code,name:s.name,expiryDate:s.expiry_date}});});
app.get('/app',auth,ensureActive,(req,res)=>res.sendFile(path.join(__dirname,'FriendsSoft.html')));
app.get('/api/license-status',auth,async(req,res)=>{const s=await schoolById(req.schoolId);const expired=s.expiry_date&&new Date().toISOString().slice(0,10)>String(s.expiry_date).slice(0,10);res.json({expired:!!expired,expiryDate:s.expiry_date||null});});

app.use('/db',auth,ensureActive);
app.get('/db/deletions',async(req,res)=>res.json({status:true,deletions:await getDeletions(req.schoolId)}));
app.get('/db/counts',async(req,res)=>res.json({status:true,counts:await countStores(req.schoolId)}));
app.get('/db/store/:store',async(req,res)=>{if(!STORES.includes(req.params.store))return res.status(404).json({status:false,message:'Unknown store'});res.json({status:true,store:req.params.store,rows:await getStore(req.schoolId,req.params.store)});});
app.get('/db/snapshot',async(req,res)=>res.json({version:2,updatedAt:new Date().toISOString(),stores:await getSnapshot(req.schoolId,String(req.query.includeActivity||'')==='1'),activityDeferred:String(req.query.includeActivity||'')!=='1'}));
app.get('/db/activity',async(req,res)=>{const limit=Math.max(1,Math.min(2000,Number(req.query.limit)||500));const r=await query('SELECT row_json FROM activity_log WHERE school_id=? AND created_at::date=CURRENT_DATE ORDER BY id DESC LIMIT ?',[req.schoolId,limit]);const rows=r.rows.map(x=>{try{return JSON.parse(x.row_json)}catch(_){return null}}).filter(Boolean);res.json({status:true,rows,total:rows.length});});
app.post('/db/activity/add',async(req,res)=>{const item=req.body&&req.body.item;if(!item||typeof item!=='object')return res.status(400).json({status:false,message:'item is required'});const row={...item,id:item.id??Date.now(),createdAt:item.createdAt||new Date().toISOString(),time:item.time||item.createdAt||new Date().toISOString()};await query('INSERT INTO activity_log(school_id,row_json) VALUES(?,?)',[req.schoolId,JSON.stringify(row)]);res.json({status:true,id:row.id});});
app.put('/db/snapshot',async(req,res)=>{const stores=req.body&&req.body.stores;if(!stores||typeof stores!=='object')return res.status(400).json({status:false,message:'stores object is required'});for(const s of STORES)if(s!=='activity')await saveStore(req.schoolId,s,Array.isArray(stores[s])?stores[s]:[]);res.json({status:true,message:'Shared database saved'});});
app.post('/db/replace',async(req,res)=>{const stores=req.body&&req.body.stores;if(!stores||typeof stores!=='object')return res.status(400).json({status:false,message:'stores object is required'});for(const s of STORES)if(s!=='activity')await saveStore(req.schoolId,s,Array.isArray(stores[s])?stores[s]:[]);await query('DELETE FROM school_deletions WHERE school_id=?',[req.schoolId]);res.json({status:true,message:'Shared database replaced',counts:await countStores(req.schoolId)});});
app.post('/db/merge',async(req,res)=>{const incoming=req.body&&req.body.stores;if(!incoming||typeof incoming!=='object')return res.status(400).json({status:false,message:'stores object is required'});const deletions=await getDeletions(req.schoolId);for(const s of STORES){if(s==='activity')continue;const current=await getStore(req.schoolId,s);const map=new Map(current.filter(x=>x&&x.id!=null).map(x=>[String(x.id),x]));for(const row of (Array.isArray(incoming[s])?incoming[s]:[])){if(!row||row.id==null||deletions[s+':'+row.id]||row.permanentlyDeletedAt)continue;const old=map.get(String(row.id));if(!old)map.set(String(row.id),row);else{const ot=Date.parse(old.updatedAt||old.createdAt||'')||0,nt=Date.parse(row.updatedAt||row.createdAt||'')||0;if(nt>=ot)map.set(String(row.id),row);}}await saveStore(req.schoolId,s,[...map.values()]);}res.json({status:true,message:'Shared database merged',stores:await countStores(req.schoolId)});});
app.post('/db/permanent-delete',async(req,res)=>{const store=String(req.body?.store||''),ids=[...new Set((Array.isArray(req.body?.ids)?req.body.ids:[]).map(Number).filter(Number.isFinite))];if(!STORES.includes(store)||!ids.length)return res.status(400).json({status:false,message:'Valid store and ids are required'});const rows=await getStore(req.schoolId,store),wanted=new Set(ids.map(String)),filtered=rows.filter(r=>!wanted.has(String(r?.id)));for(const id of ids)await query('INSERT INTO school_deletions(school_id,deletion_key,deleted_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT (school_id, deletion_key) DO UPDATE SET deleted_at=EXCLUDED.deleted_at',[req.schoolId,store+':'+id]);await saveStore(req.schoolId,store,filtered);res.json({status:true,removed:rows.length-filtered.length,store});});
app.post('/db/purge-permanent',async(req,res)=>{const d=await getDeletions(req.schoolId);let removed=0;for(const s of STORES){const rows=await getStore(req.schoolId,s),kept=rows.filter(r=>!d[s+':'+r?.id]);removed+=rows.length-kept.length;await saveStore(req.schoolId,s,kept);}res.json({status:true,removed});});

async function bridgeRequest(endpoint,method,body){return await new Promise((resolve,reject)=>{if(!bridge||bridge.readyState!==1)return reject(new Error('WhatsApp PC bridge is offline'));const id=crypto.randomUUID();const timer=setTimeout(()=>{pending.delete(id);reject(new Error('WhatsApp PC bridge timeout'));}, Number(process.env.BRIDGE_TIMEOUT_MS||3600000));pending.set(id,{resolve,reject,timer});bridge.send(JSON.stringify({type:'request',id,endpoint,method,body:body||{}}));});}
let bridge=null;const pending=new Map();
const messagingEndpoints=['/send-message','/send-bulk','/send-media','/send-result-card','/send-result-card-image','/isregistereduser','/messaging/status','/v1/device/status','/v1/sms','/sms'];
for(const ep of messagingEndpoints){app.all(ep,auth,ensureActive,async(req,res)=>{try{const r=await bridgeRequest(ep,req.method,req.method==='GET'?req.query:req.body);res.status(r.status||200).json(r.body);}catch(e){res.status(503).json({status:false,message:e.message,error:e.message});}});}

app.post('/api/migrate/import',dev,async(req,res)=>{try{const sid=Number(req.body.schoolId),stores=req.body.stores;if(!sid||!stores)return res.status(400).json({status:false,message:'schoolId and stores are required'});if(!(await schoolById(sid)))return res.status(404).json({status:false,message:'School not found'});for(const s of STORES)if(s!=='activity')await saveStore(sid,s,Array.isArray(stores[s])?stores[s]:[]);if(Array.isArray(stores.activity))for(const row of stores.activity)await query('INSERT INTO activity_log(school_id,row_json) VALUES(?,?)',[sid,JSON.stringify(row)]);res.json({status:true,message:'Migration imported',counts:await countStores(sid)});}catch(e){res.status(500).json({status:false,message:e.message});}});
app.post('/api/developer/create-school',dev,async(req,res)=>{try{const name=String(req.body.name||'New School').trim(),code=String(req.body.code||name.replace(/\W+/g,'-').toUpperCase()).trim(),username=String(req.body.username||code.toLowerCase()).trim(),password=String(req.body.password||crypto.randomBytes(6).toString('base64url')),expiry=req.body.expiryDate||process.env.DEFAULT_EXPIRY||'2099-12-31';const r=await query('INSERT INTO schools(code,name,username,password_hash,expiry_date) VALUES(?,?,?,?,?) RETURNING id',[code,name,username,hashPassword(password),expiry]);res.json({status:true,id:r.rows[0].id,code,name,username,password,expiryDate:expiry});}catch(e){res.status(400).json({status:false,message:e.message});}});
app.get('/api/developer/schools',dev,async(req,res)=>{const r=await query('SELECT id,code,name,username,active,expiry_date,created_at FROM schools ORDER BY id');res.json({status:true,schools:r});});
app.post('/api/developer/school/:id/toggle',dev,async(req,res)=>{await query('UPDATE schools SET active=NOT active WHERE id=?',[Number(req.params.id)]);const s=await schoolById(Number(req.params.id));res.json({status:true,active:!!s.active});});

const server=http.createServer(app);server.requestTimeout=0;server.headersTimeout=0;server.keepAliveTimeout=65000;
const wss=new WebSocketServer({server,path:'/bridge'});
wss.on('connection',(ws,req)=>{const key=String(req.headers['x-bridge-key']||'');if(!key||key!==DEV_KEY){ws.close(1008,'Unauthorized');return;}if(bridge&&bridge.readyState===1)try{bridge.close(1012,'Replaced by newer bridge');}catch(_){}bridge=ws;ws.send(JSON.stringify({type:'hello',ok:true}));ws.on('message',raw=>{try{const m=JSON.parse(raw.toString());if(m.type==='response'&&pending.has(m.id)){const p=pending.get(m.id);clearTimeout(p.timer);pending.delete(m.id);p.resolve({status:Number(m.status)||200,body:m.body});}}catch(_){}});ws.on('close',()=>{if(bridge===ws)bridge=null;});});

(async()=>{try{await query('SELECT 1');console.log('FriendsSoft Cloud DB connected');server.listen(PORT,'0.0.0.0',()=>console.log(`FriendsSoft Cloud running on :${PORT}`));}catch(e){console.error(e);process.exit(1);}})();
