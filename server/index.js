const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { pool, init } = require('./db');

const PORT = process.env.PORT || 10000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const HUBLA_WEBHOOK_TOKEN = process.env.HUBLA_WEBHOOK_TOKEN || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const SITE_ORIGIN = process.env.SITE_ORIGIN || 'https://clube-cde.onrender.com';
const TOKEN_TTL_DAYS = 7;

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cors({ origin: SITE_ORIGIN }));

function genToken() {
  return crypto.randomBytes(24).toString('hex');
}

function signSession(email) {
  const payload = Buffer.from(email).toString('base64url');
  const mac = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + mac;
}

function verifySession(token) {
  if (!token || token.indexOf('.') === -1) return null;
  const [payload, mac] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (mac !== expected) return null;
  try { return Buffer.from(payload, 'base64url').toString('utf8'); } catch (e) { return null; }
}

async function grantAccess(email, name, source, hublaInvoiceId) {
  email = String(email || '').trim().toLowerCase();
  if (!email) return null;
  const existing = await pool.query('SELECT * FROM members WHERE email = $1', [email]);
  if (existing.rows.length && existing.rows[0].status === 'active') {
    await pool.query(
      'UPDATE members SET name = COALESCE($2, name), source = $3, hubla_invoice_id = COALESCE($4, hubla_invoice_id) WHERE email = $1',
      [email, name || null, source, hublaInvoiceId || null]
    );
    return { email, alreadyActive: true };
  }
  const token = genToken();
  const expiresAt = new Date(Date.now() + TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);
  if (existing.rows.length) {
    await pool.query(
      `UPDATE members SET name = COALESCE($2, name), status = 'pending', source = $3, hubla_invoice_id = COALESCE($4, hubla_invoice_id),
       set_password_token = $5, token_expires_at = $6 WHERE email = $1`,
      [email, name || null, source, hublaInvoiceId || null, token, expiresAt]
    );
  } else {
    await pool.query(
      `INSERT INTO members (email, name, status, source, hubla_invoice_id, set_password_token, token_expires_at)
       VALUES ($1, $2, 'pending', $3, $4, $5, $6)`,
      [email, name || null, source, hublaInvoiceId || null, token, expiresAt]
    );
  }
  return { email, alreadyActive: false, token };
}

async function revokeAccess(email) {
  email = String(email || '').trim().toLowerCase();
  if (!email) return;
  await pool.query("UPDATE members SET status = 'revoked' WHERE email = $1", [email]);
}

/* ---------------- Health ---------------- */
app.get('/', (req, res) => res.send('clube-cde-api ok'));

/* ---------------- Hubla webhook ---------------- */
app.post('/webhooks/hubla', express.json({ limit: '1mb', type: '*/*' }), async (req, res) => {
  try {
    const incomingToken = req.get('x-hubla-token') || '';
    const tokenValid = !!HUBLA_WEBHOOK_TOKEN && incomingToken === HUBLA_WEBHOOK_TOKEN;
    try {
      await pool.query(
        'INSERT INTO webhook_log (token_valid, type, raw) VALUES ($1, $2, $3)',
        [tokenValid, (req.body && req.body.type) || null, JSON.stringify(req.body || {})]
      );
    } catch (logErr) { console.error('webhook_log insert failed', logErr); }

    if (!tokenValid) {
      return res.status(401).json({ ok: false, error: 'invalid token' });
    }
    const idempotencyKey = req.get('x-hubla-idempotency') || '';
    if (idempotencyKey) {
      try {
        await pool.query('INSERT INTO processed_webhooks (id) VALUES ($1)', [idempotencyKey]);
      } catch (e) {
        return res.status(200).json({ ok: true, dedup: true });
      }
    }

    const body = req.body || {};
    const type = body.type;
    const invoice = body.event && body.event.invoice;
    const payer = invoice && invoice.payer;
    const product = body.event && body.event.product;
    const invoiceEmail = payer && payer.email;
    const invoiceName = payer ? [payer.firstName, payer.lastName].filter(Boolean).join(' ') : null;

    const subUser = body.event && body.event.user;
    const subEmail = subUser && subUser.email;
    const subName = subUser ? [subUser.firstName, subUser.lastName].filter(Boolean).join(' ') : null;

    if (type === 'invoice.payment_succeeded' && invoiceEmail) {
      await grantAccess(invoiceEmail, invoiceName, 'hubla', invoice.id);
    } else if (type === 'invoice.refunded' && invoiceEmail) {
      await revokeAccess(invoiceEmail);
    } else if (type === 'invoice.status_updated' && invoiceEmail && invoice) {
      if (invoice.status === 'paid') {
        await grantAccess(invoiceEmail, invoiceName, 'hubla', invoice.id);
      } else if (invoice.status === 'disputed' || invoice.status === 'chargeback') {
        await revokeAccess(invoiceEmail);
      }
    } else if (type === 'subscription.activated' && subEmail) {
      await grantAccess(subEmail, subName, 'hubla', null);
    } else if (type === 'subscription.deactivated' && subEmail) {
      await revokeAccess(subEmail);
    }
    res.status(200).json({ ok: true, type: type, product: product && product.name });
  } catch (err) {
    console.error('webhook error', err);
    res.status(200).json({ ok: false });
  }
});

/* ---------------- Set password ---------------- */
app.get('/set-password/:token', async (req, res) => {
  const { rows } = await pool.query(
    'SELECT email FROM members WHERE set_password_token = $1 AND token_expires_at > now()',
    [req.params.token]
  );
  if (!rows.length) {
    return res.status(400).send(renderPage('Link inválido', '<p>Esse link expirou ou já foi usado. Peça um novo acesso.</p>'));
  }
  res.send(renderSetPasswordPage(rows[0].email, req.params.token));
});

app.post('/set-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password || String(password).length < 6) {
    return res.status(400).json({ ok: false, error: 'Senha precisa ter 6 ou mais caracteres.' });
  }
  const { rows } = await pool.query(
    'SELECT email FROM members WHERE set_password_token = $1 AND token_expires_at > now()',
    [token]
  );
  if (!rows.length) return res.status(400).json({ ok: false, error: 'Link inválido ou expirado.' });
  const hash = await bcrypt.hash(String(password), 10);
  await pool.query(
    `UPDATE members SET password_hash = $1, status = 'active', set_password_token = NULL, token_expires_at = NULL WHERE email = $2`,
    [hash, rows[0].email]
  );
  res.json({ ok: true, email: rows[0].email });
});

/* ---------------- Login ---------------- */
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, error: 'Preencha e-mail e senha.' });
  const { rows } = await pool.query('SELECT * FROM members WHERE email = $1', [String(email).trim().toLowerCase()]);
  const member = rows[0];
  if (!member || member.status !== 'active' || !member.password_hash) {
    return res.status(401).json({ ok: false, error: 'E-mail ou senha incorretos, ou acesso ainda não liberado.' });
  }
  const match = await bcrypt.compare(String(password), member.password_hash);
  if (!match) return res.status(401).json({ ok: false, error: 'E-mail ou senha incorretos.' });
  await pool.query('UPDATE members SET last_login_at = now() WHERE email = $1', [member.email]);
  res.json({ ok: true, token: signSession(member.email), name: member.name || member.email, email: member.email, avatarUrl: member.avatar_url });
});

/* ---------------- Perfil (nome / foto do próprio membro) ---------------- */
function requireSession(req, res, next) {
  const auth = req.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const email = verifySession(token);
  if (!email) return res.status(401).json({ ok: false, error: 'Sessão inválida. Entre novamente.' });
  req.memberEmail = email;
  next();
}

app.get('/me', requireSession, async (req, res) => {
  const { rows } = await pool.query('SELECT email, name, avatar_url FROM members WHERE email = $1', [req.memberEmail]);
  if (!rows.length) return res.status(404).json({ ok: false });
  res.json({ ok: true, email: rows[0].email, name: rows[0].name, avatarUrl: rows[0].avatar_url });
});

app.post('/me', requireSession, async (req, res) => {
  const { name, avatarUrl } = req.body || {};
  const cleanName = name ? String(name).trim().slice(0, 80) : null;
  const cleanAvatar = avatarUrl ? String(avatarUrl).trim().slice(0, 500) : null;
  await pool.query(
    'UPDATE members SET name = COALESCE($2, name), avatar_url = $3 WHERE email = $1',
    [req.memberEmail, cleanName, cleanAvatar]
  );
  const { rows } = await pool.query('SELECT email, name, avatar_url FROM members WHERE email = $1', [req.memberEmail]);
  res.json({ ok: true, email: rows[0].email, name: rows[0].name, avatarUrl: rows[0].avatar_url });
});

/* ---------------- Admin ---------------- */
function requireAdmin(req, res, next) {
  const auth = req.get('authorization') || '';
  const [scheme, encoded] = auth.split(' ');
  if (scheme !== 'Basic' || !encoded) {
    res.set('WWW-Authenticate', 'Basic realm="clube-cde admin"');
    return res.status(401).send('Autenticação necessária.');
  }
  const [, pass] = Buffer.from(encoded, 'base64').toString('utf8').split(':');
  const ok = ADMIN_PASSWORD && pass && pass.length === ADMIN_PASSWORD.length &&
    crypto.timingSafeEqual(Buffer.from(pass), Buffer.from(ADMIN_PASSWORD));
  if (!ok) {
    res.set('WWW-Authenticate', 'Basic realm="clube-cde admin"');
    return res.status(401).send('Senha incorreta.');
  }
  next();
}

app.get('/admin', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM members ORDER BY created_at DESC LIMIT 200');
  const logs = await pool.query('SELECT * FROM webhook_log ORDER BY received_at DESC LIMIT 10');
  res.send(renderAdminPage(rows, logs.rows));
});

app.post('/admin/grant', requireAdmin, async (req, res) => {
  const { email, name } = req.body || {};
  if (!email) return res.status(400).json({ ok: false, error: 'E-mail obrigatório.' });
  const result = await grantAccess(email, name, 'manual', null);
  if (result.alreadyActive) return res.json({ ok: true, alreadyActive: true });
  res.json({ ok: true, link: `${req.protocol}://${req.get('host')}/set-password/${result.token}` });
});

/* ---------------- HTML helpers (self-contained, no external assets) ---------------- */
function renderPage(title, bodyHtml) {
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} · Clube CDE</title>
  <style>
    body{background:#14171C;color:#EDEAE3;font-family:-apple-system,Segoe UI,Inter,sans-serif;
      display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px;box-sizing:border-box;}
    .card{max-width:420px;width:100%;background:#1B1F26;border:1px solid #2A2F38;border-radius:14px;padding:32px;}
    h1{font-size:1.3rem;margin:0 0 12px;color:#C9A227;}
    p{color:#B8B3A8;line-height:1.5;font-size:0.92rem;}
    input{width:100%;box-sizing:border-box;background:#14171C;border:1px solid #2A2F38;color:#EDEAE3;
      border-radius:8px;padding:11px 13px;font-size:0.92rem;margin-top:14px;}
    button{width:100%;margin-top:18px;background:#C9A227;color:#14171C;border:none;border-radius:8px;
      padding:12px;font-weight:700;font-size:0.92rem;cursor:pointer;}
    button:disabled{opacity:0.6;cursor:default;}
    .msg{margin-top:12px;font-size:0.85rem;}
    .msg.err{color:#E0785A;}
    .msg.ok{color:#7FB88A;}
  </style></head><body><div class="card">${bodyHtml}</div></body></html>`;
}

function renderSetPasswordPage(email, token) {
  return renderPage('Criar senha', `
    <h1>Bem-vindo ao Clube CDE</h1>
    <p>Definindo o acesso de <strong>${escapeHtml(email)}</strong>. Escolha uma senha (6 ou mais caracteres).</p>
    <form id="f">
      <input type="password" id="p1" placeholder="Nova senha" minlength="6" required>
      <input type="password" id="p2" placeholder="Confirmar senha" minlength="6" required>
      <button type="submit" id="btn">Criar senha e entrar</button>
      <div class="msg" id="msg"></div>
    </form>
    <script>
      document.getElementById('f').addEventListener('submit', async function(ev){
        ev.preventDefault();
        var p1 = document.getElementById('p1').value;
        var p2 = document.getElementById('p2').value;
        var msg = document.getElementById('msg');
        var btn = document.getElementById('btn');
        msg.className = 'msg';
        if (p1 !== p2) { msg.textContent = 'As senhas não conferem.'; msg.className = 'msg err'; return; }
        btn.disabled = true; btn.textContent = 'Criando...';
        try {
          var r = await fetch('/set-password', { method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ token: ${JSON.stringify(token)}, password: p1 }) });
          var data = await r.json();
          if (!r.ok || !data.ok) throw new Error(data.error || 'Erro ao criar senha.');
          msg.textContent = 'Senha criada! Redirecionando para o login...';
          msg.className = 'msg ok';
          setTimeout(function(){ window.location.href = '${SITE_ORIGIN}'; }, 1500);
        } catch (e) {
          msg.textContent = e.message; msg.className = 'msg err'; btn.disabled = false; btn.textContent = 'Criar senha e entrar';
        }
      });
    </script>
  `);
}

function renderAdminPage(rows, logRows) {
  const list = rows.map(function(m) {
    var linkCol = '';
    if (m.status === 'pending' && m.set_password_token) {
      linkCol = '<code style="font-size:11px;word-break:break-all;">/set-password/' + m.set_password_token + '</code>';
    }
    var lastLogin = m.last_login_at ? new Date(m.last_login_at).toLocaleString('pt-BR') : '—';
    return '<tr><td>' + escapeHtml(m.email) + '</td><td>' + escapeHtml(m.name || '') + '</td><td>' + m.status +
      '</td><td>' + m.source + '</td><td>' + new Date(m.created_at).toLocaleDateString('pt-BR') + '</td><td>' + lastLogin + '</td><td>' + linkCol + '</td></tr>';
  }).join('');
  const logList = (logRows || []).map(function(l) {
    return '<tr><td>' + new Date(l.received_at).toLocaleString('pt-BR') + '</td><td>' + (l.token_valid ? 'sim' : 'NÃO') +
      '</td><td>' + escapeHtml(l.type || '(vazio)') + '</td><td><pre style="white-space:pre-wrap;word-break:break-all;max-width:600px;margin:0;">' +
      escapeHtml(JSON.stringify(l.raw)) + '</pre></td></tr>';
  }).join('');
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin · Clube CDE</title>
  <style>
    body{background:#14171C;color:#EDEAE3;font-family:-apple-system,Segoe UI,Inter,sans-serif;margin:0;padding:32px;}
    h1{color:#C9A227;font-size:1.2rem;}
    .panel{background:#1B1F26;border:1px solid #2A2F38;border-radius:12px;padding:20px;margin-bottom:24px;max-width:520px;}
    input{background:#14171C;border:1px solid #2A2F38;color:#EDEAE3;border-radius:8px;padding:9px 12px;font-size:0.88rem;margin-right:8px;}
    button{background:#C9A227;color:#14171C;border:none;border-radius:8px;padding:9px 16px;font-weight:700;cursor:pointer;}
    table{border-collapse:collapse;width:100%;font-size:0.82rem;}
    th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2A2F38;}
    th{color:#8A8578;font-weight:600;}
    .msg{margin-top:10px;font-size:0.85rem;}
    #result{margin-top:12px;font-size:0.82rem;word-break:break-all;background:#14171C;padding:10px;border-radius:8px;display:none;}
  </style></head><body>
  <h1>Clube CDE — administração de acesso</h1>
  <div class="panel">
    <div>Dar acesso manual (a pessoa recebe um link pra criar a própria senha):</div>
    <form id="f" style="margin-top:12px;">
      <input type="email" id="email" placeholder="email@pessoa.com" required>
      <input type="text" id="name" placeholder="Nome (opcional)">
      <button type="submit">Dar acesso</button>
    </form>
    <div class="msg" id="msg"></div>
    <div id="result"></div>
  </div>
  <table>
    <thead><tr><th>E-mail</th><th>Nome</th><th>Status</th><th>Origem</th><th>Desde</th><th>Último login</th><th>Link pendente</th></tr></thead>
    <tbody>${list}</tbody>
  </table>
  <h2 style="color:#C9A227;font-size:1rem;margin-top:32px;">Últimos webhooks recebidos (diagnóstico)</h2>
  <table>
    <thead><tr><th>Quando</th><th>Token válido?</th><th>Tipo</th><th>Payload</th></tr></thead>
    <tbody>${logList || '<tr><td colspan="4">Nenhum webhook recebido ainda.</td></tr>'}</tbody>
  </table>
  <script>
    document.getElementById('f').addEventListener('submit', async function(ev){
      ev.preventDefault();
      var email = document.getElementById('email').value;
      var name = document.getElementById('name').value;
      var msg = document.getElementById('msg');
      var result = document.getElementById('result');
      msg.textContent = 'Enviando...';
      try {
        var r = await fetch('/admin/grant', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({email:email,name:name}) });
        var data = await r.json();
        if (!r.ok || !data.ok) throw new Error(data.error || 'Erro.');
        msg.textContent = '';
        if (data.alreadyActive) {
          result.style.display = 'block';
          result.textContent = 'Essa pessoa já tinha acesso ativo.';
        } else {
          result.style.display = 'block';
          result.innerHTML = 'Copie e mande esse link pra pessoa criar a senha:<br><strong>' + data.link + '</strong>';
        }
        setTimeout(function(){ window.location.reload(); }, 4000);
      } catch (e) {
        msg.textContent = e.message;
      }
    });
  </script>
  </body></html>`;
}

function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, function(c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

init().then(() => {
  app.listen(PORT, () => console.log('clube-cde-api listening on ' + PORT));
}).catch((err) => {
  console.error('failed to init db', err);
  process.exit(1);
});
