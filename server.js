// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const WebSocket = require('ws');

const APP_ID = process.env.APP_ID || '109286';
const BASE_OAUTH = 'https://oauth.deriv.com/oauth2/authorize';
const REDIRECT_PATH = '/auth/callback'; // you must set redirect URI in Deriv app settings to this endpoint
const SERVER_ORIGIN = process.env.SERVER_ORIGIN || 'http://localhost:3000'; // update in production

// encryption helpers (AES-256-GCM)
const ENC_KEY = process.env.ENCRYPTION_KEY; // 32 bytes base64 recommended
if(!ENC_KEY) {
  console.warn('Set ENCRYPTION_KEY in .env (32-byte base64). Using dev key (not for production).');
}
function encrypt(text){
  const key = Buffer.from(process.env.ENCRYPTION_KEY || 'dev_dev_dev_dev_dev_dev_dev_dev__', 'utf8').slice(0,32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}
function decrypt(b64){
  const raw = Buffer.from(b64, 'base64');
  const iv = raw.slice(0,12);
  const tag = raw.slice(12,28);
  const data = raw.slice(28);
  const key = Buffer.from(process.env.ENCRYPTION_KEY || 'dev_dev_dev_dev_dev_dev_dev_dev__', 'utf8').slice(0,32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString('utf8');
}

(async function main(){
  // open sqlite DB
  const dbfile = process.env.DB_FILE || './merrick.db';
  const db = await open({ filename: dbfile, driver: sqlite3.Database });
  // create tables
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      created_at INTEGER
    );
  `);
  await db.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      login_id TEXT,
      token_enc TEXT,
      currency TEXT,
      created_at INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  const app = express();
  app.use(cookieParser());
  app.use(bodyParser.json());

  // session config (for demo: MemoryStore). Use Redis/DB store for production.
  app.use(session({
    secret: process.env.SESSION_SECRET || 'change_me_in_prod',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false /* set true when using HTTPS */, httpOnly: true, sameSite: 'lax' }
  }));

  // helper: create or get user id in session
  app.use(async (req,res,next)=>{
    if(!req.session.user_id){
      const id = uuidv4();
      await db.run('INSERT INTO users (id, created_at) VALUES (?, ?)', [id, Date.now()]);
      req.session.user_id = id;
    }
    next();
  });

  /********* OAuth start - redirect user to Deriv login *********/
  app.get('/auth/start', (req,res) => {
    // optional affiliate params could be added here
    const state = uuidv4();
    req.session.oauth_state = state;
    const redirectUri = ${SERVER_ORIGIN}${REDIRECT_PATH};
    // Deriv's docs: redirect to https://oauth.deriv.com/oauth2/authorize?app_id=YOUR_APP_ID&redirect_uri=...
    // They will redirect back with acct1/token1/cur1 etc. We include state to match.
    const url = ${BASE_OAUTH}?app_id=${encodeURIComponent(APP_ID)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${encodeURIComponent(state)};
    return res.redirect(url);
  });

  /********* OAuth callback - Deriv will redirect with query params acctN/tokenN/curN *********/
  app.get(REDIRECT_PATH, async (req,res) => {
    // Deriv returns tokens in query string like ?acct1=CR...&token1=a1-...&cur1=USD&state=...
    const query = req.query;
    if(!query) return res.status(400).send('No query params from Deriv OAuth.');
    // optional: validate state
    if(req.session.oauth_state && query.state && req.session.oauth_state !== query.state){
      console.warn('OAuth state mismatch - continuing but check security');
    }
    // Extract accounts
    const accountsFound = [];
    for(let i=1;i<=10;i++){
      const acct = query['acct'+i];
      const token = query['token'+i];
      const cur = query['cur'+i];
      if(acct && token){
        accountsFound.push({acct, token, cur: cur || 'USD'});
      }
    }
    if(accountsFound.length===0){
      return res.status(400).send('No accounts returned by provider.');
    }
    // Store each account encrypted in DB for this session user
    const userId = req.session.user_id;
    for(const a of accountsFound){
      const id = uuidv4();
      const enc = encrypt(a.token);
      await db.run('INSERT INTO accounts (id, user_id, login_id, token_enc, currency, created_at) VALUES (?,?,?,?,?,?)',
        [id, userId, a.acct, enc, a.cur, Date.now()]);
    }
    // persist then redirect to front-end user page (your app)
    // If your front-end root is at '/', change as needed
    return res.redirect('/');
  });

  /********* API: list accounts for current user (no token in response) *********/
  app.get('/api/accounts', async (req,res) => {
    const userId = req.session.user_id;
    const rows = await db.all('SELECT id, login_id, currency, created_at FROM accounts WHERE user_id = ?', [userId]);
    return res.json({ accounts: rows });
  });

  /********* API: get account details server-side (internal only) *********/
  async function getAccountByIdForUser(userId, accountId){
    const row = await db.get('SELECT * FROM accounts WHERE id = ? AND user_id = ?', [accountId, userId]);
    if(!row) return null;
    return { id: row.id, login_id: row.login_id, currency: row.currency, token: decrypt(row.token_enc) };
  }

  /********* Helper: open a WS connection to Deriv and send/receive a single request (authorize -> request -> listen) *********/
  function derivRequestWithToken(token, requestObj, timeout = 10000){
    // Returns a Promise that resolves with the first response for the request or rejects on timeout/error.
    return new Promise((resolve, reject)=>{
      const url = wss://ws.binaryws.com/websockets/v3?app_id=${APP_ID};
      const ws = new WebSocket(url);
      let cleaned = false;
      const timer = setTimeout(()=> {
        if(!cleaned){ cleaned = true; ws.terminate(); reject(new Error('Deriv WS timeout')); }
      }, timeout);

      ws.on('open', ()=>{
        // authorize
        ws.send(JSON.stringify({ authorize: token }));
      });
      ws.on('message', (msg) => {
        try{
          const data = JSON.parse(msg.toString());
          // check authorize response
          if(data.authorize){
            // now send requested call
            ws.send(JSON.stringify(requestObj));
            return;
          }
          // if this message contains the response we're waiting for, resolve
          // We'll resolve with any object that is not an error for simplicity.
          if(data.error){
            if(!cleaned){ cleaned=true; clearTimeout(timer); ws.close(); reject(data.error); }
            return;
          }
          // Many responses come -- resolve with the first non-authorize message
          if(!cleaned){
            cleaned = true;
            clearTimeout(timer);
            ws.close();
            resolve(data);
          }
        }catch(e){
          if(!cleaned){ cleaned=true; clearTimeout(timer); ws.close(); reject(e); }
        }
      });
      ws.on('error', (err) => {
        if(!cleaned){ cleaned=true; clearTimeout(timer); ws.terminate(); reject(err); }
      });
      ws.on('close', ()=>{ /* noop */ });
    });
  }

  /********* API: request balance for an account *********/
  app.get('/api/balance/:accountId', async (req,res) => {
    const userId = req.session.user_id;
    const account = await getAccountByIdForUser(userId, req.params.accountId);
    if(!account) return res.status(404).json({ error: 'Account not found' });
    try{
      const resp = await derivRequestWithToken(account.token, { balance: 1 }, 10000);
      return res.json({ ok: true, resp });
    }catch(err){
      return res.status(500).json({ error: String(err) });
    }
  });

  /********* API: get proposal (server-side) *********/
  app.post('/api/proposal', async (req,res) => {
    const userId = req.session.user_id;
    const { accountId, symbol, amount, contract_type, duration, duration_unit = 's', basis='stake' } = req.body;
    if(!accountId || !symbol || !amount || !contract_type) return res.status(400).json({ error: 'Missing parameters' });
    const account = await getAccountByIdForUser(userId, accountId);
    if(!account) return res.status(404).json({ error: 'Account not found' });
    try{
      // build proposal request
      const proposalReq = {
        proposal: 1,
        subscribe: 1,
        amount,
        basis,
        contract_type,
        currency: account.currency || 'USD',
        duration,
        duration_unit,
        symbol
      };
      const resp = await derivRequestWithToken(account.token, proposalReq, 10000);
      // keep the proposal in server memory? For simplicity we'll return the proposal to client,
      // and the client will request /api/buy to execute using same parameters (server re-requests buy).
      return res.json({ ok: true, proposal: resp });
    }catch(err){
      return res.status(500).json({ error: String(err) });
    }
  });

  /********* API: buy (execute) *********/
  app.post('/api/buy', async (req,res) => {
    const userId = req.session.user_id;
    const { accountId, symbol, amount, contract_type, duration, duration_unit = 's', basis='stake' } = req.body;
    if(!accountId || !symbol || !amount || !contract_type) return res.status(400).json({ error: 'Missing parameters' });
    const account = await getAccountByIdForUser(userId, accountId);
    if(!account) return res.status(404).json({ error: 'Account not found' });
    try{
      // Build buy request (some Deriv endpoints accept buy:1 with contract details)
      const buyReq = {
        buy: 1,
        subscribe: 1,
        price: amount,
        symbol,
        contract_type,
        basis,
        currency: account.currency || 'USD',
        duration,
        duration_unit
      };
      const resp = await derivRequestWithToken(account.token, buyReq, 15000);
      // On success, return server-side response
      return res.json({ ok: true, buy: resp });
    }catch(err){
      return res.status(500).json({ error: String(err) });
    }
  });

  /********* API: list accounts (detailed) - returns id/login/currency *********/
  app.get('/api/accounts/detailed', async (req,res) => {
    const userId = req.session.user_id;
    const rows = await db.all('SELECT id, login_id, currency, created_at FROM accounts WHERE user_id = ?', [userId]);
    return res.json({ accounts: rows });
  });

  /********* Serve frontend (optional) *********/
  // If you host the front-end from this server, serve static files from ./public
  app.use(express.static('public'));

  // Start server
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, ()=> console.log('Server started on port', PORT));
})();
