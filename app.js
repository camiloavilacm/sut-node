import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {randomBytes, scrypt as scryptCallback, timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import pg from 'pg';
import jwt from 'jsonwebtoken';
const scrypt = promisify(scryptCallback);
const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) throw new Error('JWT_SECRET must have at least 32 characters');
const pool = new pg.Pool({connectionString:process.env.DATABASE_URL, max:10});
const root = new URL('.', import.meta.url);
const read = name => readFile(new URL(name, root));
async function hash(password) {
  const salt = randomBytes(32);
  const value = await scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:64*1024*1024});
  return salt.toString('hex')+':'+value.toString('hex');
}
async function matches(password, value) {
  const [salt, expected] = value.split(':');
  const actual = await scrypt(password,Buffer.from(salt,'hex'),64,{N:16384,r:8,p:1,maxmem:64*1024*1024});
  return timingSafeEqual(actual,Buffer.from(expected,'hex'));
}
async function seed() {
  const baseline = JSON.parse(await read('contracts/data/baseline.json')).users[0];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(2002)');
    await client.query((await read('db/schema.sql')).toString());
    await client.query('INSERT INTO users (username,email,password_hash,bio,image,baseline) VALUES ($1,$2,$3,$4,$5,true) ON CONFLICT DO NOTHING',[baseline.username,baseline.email,await hash(baseline.password),baseline.bio,baseline.image]);
    const user = (await client.query('SELECT * FROM users WHERE baseline')).rows[0];
    if (!user || ['username','email','bio','image'].some(k=>user[k]!==baseline[k]) || !await matches(baseline.password,user.password_hash)) throw new Error('Baseline drift: refusing to overwrite');
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
function envelope(user, token) {
  token ||= jwt.sign({},secret,{algorithm:'HS256',subject:String(user.id),expiresIn:3600,issuer:'sut-node'});
  return {user:{email:user.email,username:user.username,bio:user.bio,image:user.image,token}};
}
function send(res,status,data) { res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(data)); }
const invalid = res => send(res,422,{errors:{'email or password':['is invalid']}});
async function input(req, register) {
  if (!req.headers['content-type']?.startsWith('application/json')) return null;
  let size=0; const chunks=[];
  for await (const chunk of req) { size+=chunk.length;if(size>16384) return null;chunks.push(chunk); }
  let data;
  try { data=JSON.parse(Buffer.concat(chunks).toString()); } catch { return null; }
  if (!data || Array.isArray(data) || Object.keys(data).join()!=='user' || !data.user || Array.isArray(data.user)) return null;
  const u=data.user, keys=register?['email','password','username']:['email','password'];
  if (Object.keys(u).sort().join()!==keys.join() || Object.values(u).some(v=>typeof v!=='string')) return null;
  if (u.password.length<8 || Buffer.byteLength(u.password)>1024 || !u.email.includes('@') || u.email.length>320) return null;
  if (register && (!u.username.length || [...u.username].length>64)) return null;
  return u;
}
await seed();
if (process.argv.includes('--seed')) { await pool.end();process.exit(0); }
const server = http.createServer(async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  try {
    const path = new URL(req.url,'http://localhost').pathname;
    if (req.method==='POST' && path==='/api/users') {
      const u=await input(req,true);if(!u)return invalid(res);
      try {
        const row=(await pool.query('INSERT INTO users (username,email,password_hash) VALUES ($1,$2,$3) RETURNING *',[u.username,u.email,await hash(u.password)])).rows[0];
        return send(res,201,envelope(row));
      } catch(e) { if(e.code==='23505') return send(res,422,{errors:{identity:['is already taken']}});throw e; }
    }
    if (req.method==='POST' && path==='/api/users/login') {
      const u=await input(req,false);if(!u)return invalid(res);
      const row=(await pool.query('SELECT * FROM users WHERE email=$1',[u.email])).rows[0];
      if(!row || !await matches(u.password,row.password_hash))return invalid(res);
      return send(res,200,envelope(row));
    }
    if (req.method==='GET' && path==='/api/user') {
      const header=req.headers.authorization || '';
      const deny=()=>send(res,401,{errors:{auth:['unauthorized']}});
      if(!/^Token [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(header))return deny();
      const token=header.slice(6);let claims;
      try {
        claims=jwt.verify(token,secret,{algorithms:['HS256'],issuer:'sut-node'});
        if(typeof claims.sub!=='string' || !/^\d+$/.test(claims.sub) || !Number.isInteger(claims.exp) || !Number.isInteger(claims.iat))return deny();
      } catch { return deny(); }
      const row=(await pool.query('SELECT * FROM users WHERE id=$1',[claims.sub])).rows[0];
      if(!row)return deny();return send(res,200,envelope(row,token));
    }
    if(req.method==='GET' && path==='/health') {await pool.query('SELECT 1');return send(res,200,{status:'ok'});}
    const files={'/':'index.html','/login':'index.html','/register':'index.html','/settings':'index.html','/assets/app.js':'assets/app.js','/assets/style.css':'assets/style.css'};
    if(req.method==='GET' && files[path]) {
      res.writeHead(200,{'Content-Type':path.endsWith('.js')?'text/javascript':path.endsWith('.css')?'text/css':'text/html'});
      return res.end(await read('frontend/'+files[path]));
    }
    return send(res,404,{errors:{route:['not found']}});
  } catch { if(!res.headersSent)send(res,500,{errors:{server:['unavailable']}});else res.end(); }
});
server.listen(8000,'0.0.0.0');
process.on('SIGTERM',()=>server.close(async()=>{await pool.end();process.exit(0);}));
