/**
 * Nesfera RH — Backend API
 * Node.js + Express + Supabase + Brevo API + Evolution API
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middlewares ────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve o HTML principal (quando colocado na pasta /public)
app.use(express.static(path.join(__dirname, 'public')));

// ─── Supabase ────────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ─── Helpers ─────────────────────────────────────────────────────────────────
function hashPwd(str) {
  // Mesmo algoritmo simples usado no front-end
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h = ((h << 5) - h) + c;
    h |= 0;
  }
  return h.toString(16);
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }
  try {
    const decoded = jwt.verify(auth.slice(7), process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token inválido ou expirado' });
  }
}

// Nomes válidos de stores (whitelist de segurança)
const VALID_STORES = [
  'funcionarios', 'documentos', 'historico', 'nesfera_docs',
  'beneficios', 'config', 'descontos', 'ferias', 'usuarios'
];

// ─── Health ──────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── LOGIN ───────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
  }

  try {
    const hash = hashPwd(password);

    // Verifica config (admin principal)
    const { data: configs } = await supabase
      .from('config')
      .select('data')
      .eq('id', 1)
      .single();

    let adminOk = false;
    let loginNome = username;

    if (configs && configs.data) {
      const cfg = configs.data;
      if (username === cfg.adminUser && hash === cfg.adminHash) {
        adminOk = true;
        loginNome = cfg.adminUser;
      }
    }

    // Verifica usuarios extras
    if (!adminOk) {
      const { data: usuarios } = await supabase
        .from('usuarios')
        .select('data');

      if (usuarios && Array.isArray(usuarios)) {
        const match = usuarios.find(row => {
          const u = row.data;
          return u && u.ativo !== false && u.username === username && u.hash === hash;
        });
        if (match) {
          adminOk = true;
          loginNome = match.data.nome || match.data.username;
        }
      }
    }

    if (!adminOk) {
      return res.status(401).json({ error: 'Usuário ou senha incorretos' });
    }

    const token = jwt.sign(
      { username, nome: loginNome },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, nome: loginNome });
  } catch (e) {
    console.error('Erro no login:', e);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// ─── ENVIO DE EMAIL (Brevo API v3 — HTTP, sem SMTP) ─────────────────────────
app.post('/api/send-email', authMiddleware, async (req, res) => {
  const { to, toName, subject, message, html, attachments } = req.body;

  if (!to) return res.status(400).json({ error: 'Destinatário obrigatório' });

  try {
    const fromName  = process.env.SMTP_FROM_NAME  || 'Andaimes Nesfera';
    const fromEmail = process.env.SMTP_FROM_EMAIL || 'rh@andaimesnesfera.com';
    const emailSubject = subject || `Documentos Nesfera — ${toName || to}`;

    const htmlContent = html || (message
      ? `<div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.6">${message.replace(/\n/g, '<br>')}</div>`
      : '<p>Documentos em anexo.</p>');

    // Monta anexos no formato Brevo API
    const brevoAttachments = [];
    if (Array.isArray(attachments)) {
      for (const att of attachments) {
        if (!att.data) continue;
        let base64Data = att.data;
        if (base64Data.includes(',')) base64Data = base64Data.split(',')[1];
        brevoAttachments.push({
          content: base64Data,
          name: att.filename || 'documento.pdf'
        });
      }
    }

    const replyToEmail = process.env.SMTP_REPLY_TO || process.env.SMTP_USER_EMAIL || fromEmail;

    const payload = {
      sender:      { name: fromName, email: fromEmail },
      to:          [{ email: to, name: toName || to }],
      replyTo:     { email: replyToEmail, name: fromName },
      subject:     emailSubject,
      htmlContent: htmlContent
    };
    if (brevoAttachments.length > 0) payload.attachment = brevoAttachments;

    const resp = await fetch('https://api.brevo.com/v3/smtp/email', {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        'api-key': process.env.BREVO_API_KEY
      },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error('Brevo API erro:', resp.status, errText);
      throw new Error(`Brevo ${resp.status}: ${errText}`);
    }

    const result = await resp.json();
    console.log('✅ Email enviado via Brevo API:', result.messageId);
    res.json({ success: true, message: 'E-mail enviado com sucesso', messageId: result.messageId });
  } catch (e) {
    console.error('Erro ao enviar e-mail:', e);
    res.status(500).json({ error: 'Falha ao enviar e-mail: ' + e.message });
  }
});

// ─── ENVIO DE WHATSAPP (Evolution API) ───────────────────────────────────────
app.post('/api/send-whatsapp', authMiddleware, async (req, res) => {
  const { phone, message, attachments } = req.body;

  if (!phone) return res.status(400).json({ error: 'Telefone obrigatório' });

  const EVOLUTION_URL = process.env.EVOLUTION_API_URL;
  const EVOLUTION_INST = process.env.EVOLUTION_INSTANCE;
  const EVOLUTION_KEY  = process.env.EVOLUTION_API_KEY;

  if (!EVOLUTION_URL || !EVOLUTION_INST || !EVOLUTION_KEY) {
    return res.status(500).json({ error: 'Evolution API não configurada. Verifique as variáveis de ambiente.' });
  }

  const headers = {
    'Content-Type': 'application/json',
    'apikey': EVOLUTION_KEY
  };

  const cleanPhone = phone.replace(/\D/g, '');
  const phoneWithCountry = cleanPhone.startsWith('55') ? cleanPhone : '55' + cleanPhone;

  try {
    const results = [];

    if (message) {
      const textResp = await fetch(
        `${EVOLUTION_URL}/message/sendText/${EVOLUTION_INST}`,
        {
          method: 'POST',
          headers,
          body: JSON.stringify({ number: phoneWithCountry, text: message })
        }
      );
      const textData = await textResp.json();
      if (!textResp.ok) {
        throw new Error('Falha ao enviar texto WhatsApp: ' + JSON.stringify(textData));
      }
      results.push({ type: 'text', status: 'sent' });
    }

    if (Array.isArray(attachments) && attachments.length > 0) {
      for (const att of attachments) {
        if (!att.data) continue;

        let base64Data = att.data;
        let mimeType = att.mimeType || 'application/octet-stream';

        if (base64Data.includes(',')) {
          const parts = base64Data.split(',');
          if (parts[0].includes(':') && parts[0].includes(';')) {
            mimeType = parts[0].split(':')[1].split(';')[0];
          }
          base64Data = parts[1];
        }

        const mediaResp = await fetch(
          `${EVOLUTION_URL}/message/sendMedia/${EVOLUTION_INST}`,
          {
            method: 'POST',
            headers,
            body: JSON.stringify({
              number: phoneWithCountry,
              mediatype: getMediaType(mimeType),
              mimetype: mimeType,
              caption: att.filename || '',
              media: base64Data,
              fileName: att.filename || 'documento'
            })
          }
        );
        const mediaData = await mediaResp.json();
        if (!mediaResp.ok) {
          console.error('Falha ao enviar arquivo:', mediaData);
          results.push({ type: 'media', filename: att.filename, status: 'error', error: JSON.stringify(mediaData) });
        } else {
          results.push({ type: 'media', filename: att.filename, status: 'sent' });
        }
      }
    }

    res.json({ success: true, results });
  } catch (e) {
    console.error('Erro ao enviar WhatsApp:', e);
    res.status(500).json({ error: 'Falha ao enviar WhatsApp: ' + e.message });
  }
});

// ─── CRUD GENÉRICO ───────────────────────────────────────────────────────────
// GET /api/:store → lista todos
app.get('/api/:store', authMiddleware, async (req, res) => {
  const { store } = req.params;
  if (!VALID_STORES.includes(store)) {
    return res.status(400).json({ error: 'Store inválido' });
  }
  try {
    const { data, error } = await supabase.from(store).select('id, data');
    if (error) throw error;
    // Retorna array no mesmo formato do IndexedDB: [{id, ...data}]
    const result = (data || []).map(row => ({ id: row.id, ...row.data }));
    res.json(result);
  } catch (e) {
    console.error(`GET /${store}:`, e);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/:store/:id → busca um
app.get('/api/:store/:id', authMiddleware, async (req, res) => {
  const { store, id } = req.params;
  if (!VALID_STORES.includes(store)) {
    return res.status(400).json({ error: 'Store inválido' });
  }
  try {
    const { data, error } = await supabase
      .from(store)
      .select('id, data')
      .eq('id', id)
      .single();
    if (error) {
      if (error.code === 'PGRST116') return res.status(404).json({ error: 'Não encontrado' });
      throw error;
    }
    res.json({ id: data.id, ...data.data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/:store → adiciona (sem id, auto-incremento)
app.post('/api/:store', authMiddleware, async (req, res) => {
  const { store } = req.params;
  if (!VALID_STORES.includes(store)) {
    return res.status(400).json({ error: 'Store inválido' });
  }
  try {
    const { id: _id, ...dataFields } = req.body;
    const { data, error } = await supabase
      .from(store)
      .insert({ data: dataFields })
      .select('id, data')
      .single();
    if (error) throw error;
    res.status(201).json({ id: data.id, ...data.data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/:store/upsert → insere ou atualiza (usado para config com id fixo)
app.put('/api/:store/upsert', authMiddleware, async (req, res) => {
  const { store } = req.params;
  if (!VALID_STORES.includes(store)) {
    return res.status(400).json({ error: 'Store inválido' });
  }
  try {
    const { id, ...dataFields } = req.body;
    if (!id) return res.status(400).json({ error: 'ID obrigatório para upsert' });

    const { data, error } = await supabase
      .from(store)
      .upsert({ id, data: dataFields }, { onConflict: 'id' })
      .select('id, data')
      .single();
    if (error) throw error;
    res.json({ id: data.id, ...data.data });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/:store/:id → remove
app.delete('/api/:store/:id', authMiddleware, async (req, res) => {
  const { store, id } = req.params;
  if (!VALID_STORES.includes(store)) {
    return res.status(400).json({ error: 'Store inválido' });
  }
  try {
    const { error } = await supabase.from(store).delete().eq('id', id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Determina o tipo de mídia para a Evolution API
function getMediaType(mimeType) {
  if (!mimeType) return 'document';
  if (mimeType.startsWith('image/')) return 'image';
  if (mimeType.startsWith('video/')) return 'video';
  if (mimeType.startsWith('audio/')) return 'audio';
  return 'document';
}

// ─── STATUS DO WHATSAPP ───────────────────────────────────────────────────────
app.get('/api/whatsapp/status', authMiddleware, async (req, res) => {
  const EVOLUTION_URL = process.env.EVOLUTION_API_URL;
  const EVOLUTION_INST = process.env.EVOLUTION_INSTANCE;
  const EVOLUTION_KEY  = process.env.EVOLUTION_API_KEY;

  if (!EVOLUTION_URL || !EVOLUTION_INST || !EVOLUTION_KEY) {
    return res.json({ connected: false, reason: 'Não configurado' });
  }

  try {
    const resp = await fetch(
      `${EVOLUTION_URL}/instance/connectionState/${EVOLUTION_INST}`,
      { headers: { 'apikey': EVOLUTION_KEY } }
    );
    const data = await resp.json();
    const connected = data?.instance?.state === 'open';
    res.json({ connected, state: data?.instance?.state, qrcode: data?.qrcode });
  } catch (e) {
    res.json({ connected: false, reason: e.message });
  }
});

// ─── QR CODE DO WHATSAPP ─────────────────────────────────────────────────────
app.get('/api/whatsapp/qrcode', authMiddleware, async (req, res) => {
  const EVOLUTION_URL = process.env.EVOLUTION_API_URL;
  const EVOLUTION_INST = process.env.EVOLUTION_INSTANCE;
  const EVOLUTION_KEY  = process.env.EVOLUTION_API_KEY;

  try {
    const resp = await fetch(
      `${EVOLUTION_URL}/instance/connect/${EVOLUTION_INST}`,
      { headers: { 'apikey': EVOLUTION_KEY } }
    );
    const data = await resp.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── INICIALIZAÇÃO DO BANCO (config padrão) ──────────────────────────────────
async function initDatabase() {
  try {
    // Verifica se já existe config
    const { data } = await supabase.from('config').select('id').eq('id', 1).single();
    if (!data) {
      // Cria config padrão com admin
      const defaultConfig = {
        adminUser: 'admin',
        adminHash: hashPwd('Ne1505@15'),
        valorCafe: 8,
        valorAlimentacao: 0,
        alimentacao_opcoes: ['Marmitex','Restaurante','Vale-alimentação','Não recebe'],
        almoco_opcoes: ['Marmitex','Restaurante','Vale-refeição','Não recebe'],
        passagem_opcoes: ['Vale-transporte','Próprio','Moto','Não recebe'],
        cargos: ['Operador de Andaime','Montador','Auxiliar','Supervisor','Administrativo','Almoxarife','Motorista','Encarregado']
      };
      await supabase.from('config').upsert({ id: 1, data: defaultConfig });
      console.log('✅ Config padrão criada (admin/Ne1505@15)');
    } else {
      console.log('✅ Config já existe no banco');
    }
  } catch (e) {
    console.error('⚠️  Erro ao inicializar banco (tabela pode não existir ainda):', e.message);
  }
}

// ─── START ───────────────────────────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`\n🚀 Nesfera RH Backend rodando na porta ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  await initDatabase();
});
