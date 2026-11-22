/**
 * BOUA AI — Serveur « BOUA Cloud » (fonction Vercel Edge)
 * ------------------------------------------------------------------
 * - Garde la clé Gemini SECRÈTE côté serveur (variable d'environnement Vercel GEMINI_API_KEY)
 * - Réponses en temps réel (streaming) + recherche Google pour des infos à jour
 * - Accès réservé aux utilisateurs connectés à BOUA AI (jeton Firebase vérifié)
 * - Limite de débit par utilisateur, contrôle de taille, origines autorisées (CORS)
 * - Choisit automatiquement le meilleur modèle Gemini « Flash » disponible
 *
 * Variables d'environnement (Vercel → Settings → Environment Variables) :
 *   GEMINI_API_KEY      (obligatoire) clé créée sur https://aistudio.google.com/apikey
 *   GEMINI_API_KEY_2, GEMINI_API_KEY_3 (facultatif) clés de secours : si une clé atteint son quota, la suivante prend le relais
 *   GEMINI_API_KEYS     (facultatif)  autres clés, séparées par des virgules
 *   OPENAI_API_KEY      (facultatif)  ChatGPT  — aussi accepté : CHATGPT_API_KEY      | OPENAI_MODEL pour forcer un modèle
 *   ANTHROPIC_API_KEY   (facultatif)  Claude   — aussi accepté : CLAUDE_API_KEY       | CLAUDE_MODEL pour forcer un modèle
 *   DEEPSEEK_API_KEY    (facultatif)  DeepSeek                                     | DEEPSEEK_MODEL pour forcer un modèle
 *   BOUA_ENGINE_ORDER   (facultatif)  ordre des moteurs, ex. « gemini,claude,openai,deepseek » (par défaut)
 *   GEMINI_MODEL        (facultatif)  forcer un modèle texte précis
 *   GEMINI_IMAGE_MODEL  (facultatif)  forcer un modèle d'image précis
 *   FIREBASE_PROJECT_ID (facultatif)  par défaut : boui-ia
 *   ALLOWED_ORIGINS     (facultatif)  domaines autorisés en plus, séparés par des virgules
 */

export const config = { runtime: 'edge' };

const PROJECT_ID = (typeof process !== 'undefined' && process.env.FIREBASE_PROJECT_ID) || 'boui-ia';
const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta';
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

const MAX_BODY_BYTES = 4 * 1024 * 1024; // limite Vercel ≈ 4,5 Mo
const MAX_CONTENTS = 200;
const RATE_LIMIT_PER_MIN = 20;

const env = (k) => (typeof process !== 'undefined' && process.env[k]) || '';

/* ---------------- CORS ---------------- */
function allowedOrigin(req) {
  const origin = req.headers.get('origin') || '';
  if (!origin) return '';
  const self = new URL(req.url).origin;
  const extra = env('ALLOWED_ORIGINS')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const ok =
    origin === self ||
    origin === 'https://appassets.androidplatform.net' || // application Android BOUA AI
    /^http:\/\/localhost(:\d+)?$/.test(origin) ||
    extra.includes(origin);
  return ok ? origin : '';
}

function corsHeaders(origin) {
  const h = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
  if (origin) h['Access-Control-Allow-Origin'] = origin;
  return h;
}

function jsonError(status, message, origin) {
  return new Response(JSON.stringify({ error: { message } }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders(origin) },
  });
}

/* ---------------- Vérification du jeton Firebase (RS256, sans dépendance) ---------------- */
let jwksCache = { keys: null, exp: 0 };

function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const b64urlJson = (s) => JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));

async function getJwks() {
  if (jwksCache.keys && Date.now() < jwksCache.exp) return jwksCache.keys;
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error('Clés Google indisponibles');
  const data = await res.json();
  const maxAge = Number((res.headers.get('cache-control') || '').match(/max-age=(\d+)/)?.[1] || 3600);
  jwksCache = { keys: data.keys || [], exp: Date.now() + Math.min(maxAge, 21600) * 1000 };
  return jwksCache.keys;
}

export async function verifyFirebaseIdToken(token, projectId = PROJECT_ID, nowSec = Math.floor(Date.now() / 1000), jwksOverride = null) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('Jeton invalide');
  const header = b64urlJson(parts[0]);
  const payload = b64urlJson(parts[1]);
  if (header.alg !== 'RS256' || !header.kid) throw new Error('Jeton invalide');
  if (payload.aud !== projectId) throw new Error('Jeton d’un autre projet');
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) throw new Error('Émetteur invalide');
  if (!payload.sub || typeof payload.sub !== 'string' || payload.sub.length > 128) throw new Error('Utilisateur invalide');
  if (!(payload.exp > nowSec)) throw new Error('Session expirée, reconnectez-vous');
  if (!(payload.iat <= nowSec + 300)) throw new Error('Jeton invalide');

  const keys = jwksOverride || (await getJwks());
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('Clé de signature inconnue');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    b64urlToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1])
  );
  if (!ok) throw new Error('Signature invalide');
  return payload;
}

/* ---------------- Limite de débit (par instance) ---------------- */
const hits = new Map();
function rateLimited(uid, max = RATE_LIMIT_PER_MIN) {
  const now = Date.now();
  const arr = (hits.get(uid) || []).filter((t) => now - t < 60000);
  if (arr.length >= max) {
    hits.set(uid, arr);
    return true;
  }
  arr.push(now);
  hits.set(uid, arr);
  if (hits.size > 5000) hits.clear();
  return false;
}

/* ---------------- Choix automatique du modèle Gemini ---------------- */
let modelCache = { text: [], image: [], exp: 0 };
// Modèles temporairement écartés (quota nul, retirés…) pour aller directement vers un modèle qui répond
const badModels = new Map(); // nom -> horodatage de fin d'exclusion
const isBad = (m) => (badModels.get(m) || 0) > Date.now();
const markBad = (m, ms) => badModels.set(m, Date.now() + ms);

function versionOf(name) {
  const m = name.match(/gemini-(\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : 0;
}

/**
 * Liste ordonnée des modèles à essayer :
 * 1) Flash stables (du plus récent au plus ancien) → 2) Flash-Lite stables (quotas gratuits plus larges)
 * 3) alias « latest » → 4) versions « preview » (souvent quota gratuit nul)
 */
export function pickModels(models) {
  const gen = models.filter((m) => (m.supportedGenerationMethods || []).includes('generateContent')).map((m) => m.name.replace(/^models\//, ''));
  const notSpecial = (n) => !/(image|tts|audio|live|embedding|vision|thinking|robotics|computer|exp|customtools|-\d{3,}$)/.test(n);
  // Les modèles Gemini 2.x sont retirés par Google (« no longer available to new users »)
  const flash = gen.filter((n) => /^gemini-[\d.]+-flash/.test(n) && notSpecial(n) && versionOf(n) >= 3);
  const byVersion = (a, b) => versionOf(b) - versionOf(a);
  const stable = flash.filter((n) => !/preview/.test(n));
  const text = [
    ...stable.filter((n) => !/lite/.test(n)).sort(byVersion),
    ...stable.filter((n) => /lite/.test(n)).sort(byVersion),
    ...gen.filter((n) => /^gemini-flash(-lite)?-latest$/.test(n)),
    ...flash.filter((n) => /preview/.test(n)).sort(byVersion),
  ];
  const images = gen.filter((n) => /^gemini-[\d.]+-flash.*image/.test(n) && !/tts|audio|live/.test(n) && versionOf(n) >= 3);
  const imageList = [...images.filter((n) => !/preview/.test(n)).sort(byVersion), ...images.filter((n) => /preview/.test(n)).sort(byVersion)];
  return { text: [...new Set(text)], image: imageList };
}

async function resolveModels(apiKey, force = false) {
  if (!force && modelCache.text.length && Date.now() < modelCache.exp) return modelCache;
  let picked = { text: [], image: [] };
  try {
    const res = await fetch(`${GEMINI_BASE}/models?pageSize=1000`, { headers: { 'x-goog-api-key': apiKey } });
    if (res.ok) picked = pickModels((await res.json()).models || []);
  } catch (e) {}
  const forcedText = env('GEMINI_MODEL');
  const forcedImage = env('GEMINI_IMAGE_MODEL');
  const text = [...new Set([forcedText, ...picked.text, 'gemini-flash-latest', 'gemini-flash-lite-latest'].filter(Boolean))];
  const image = [...new Set([forcedImage, ...picked.image].filter(Boolean))];
  modelCache = { text, image, exp: Date.now() + 6 * 3600 * 1000 };
  return modelCache;
}

/* ---------------- Moteurs supplémentaires : ChatGPT, Claude, DeepSeek ---------------- */
const firstEnv = (...names) => names.map((n) => env(n).trim()).find(Boolean) || '';
export function engineKeys() {
  return {
    openai: firstEnv('OPENAI_API_KEY', 'CHATGPT_API_KEY', 'OPENAI_KEY', 'CHATGPT_KEY'),
    claude: firstEnv('ANTHROPIC_API_KEY', 'CLAUDE_API_KEY', 'ANTHROPIC_KEY', 'CLAUDE_KEY'),
    deepseek: firstEnv('DEEPSEEK_API_KEY', 'DEEPSEEK_KEY'),
  };
}
const ENGINE_LABELS = { gemini: 'Gemini', openai: 'ChatGPT', claude: 'Claude', deepseek: 'DeepSeek' };

const otherModelCache = {}; // moteur -> { model, exp }
export function pickOpenAIModel(ids) {
  const re = /^gpt-(\d+(?:\.\d+)?)(-mini)?$/;
  const list = ids.map((id) => ({ id, m: id.match(re) })).filter((x) => x.m);
  // Récent + économique : la version « mini » la plus récente, sinon la version standard la plus récente
  list.sort((a, b) => parseFloat(b.m[1]) - parseFloat(a.m[1]) || (b.m[2] ? 1 : 0) - (a.m[2] ? 1 : 0));
  return list[0]?.id || 'gpt-4o-mini';
}
export function pickClaudeModel(models) {
  // La liste Anthropic est triée du plus récent au plus ancien : on prend le Sonnet le plus récent
  const ids = models.map((m) => m.id || '');
  return ids.find((id) => /sonnet/.test(id)) || ids[0] || 'claude-sonnet-4-5';
}
async function resolveOtherModel(engine, key) {
  const forced = { openai: env('OPENAI_MODEL'), claude: env('CLAUDE_MODEL'), deepseek: env('DEEPSEEK_MODEL') }[engine];
  if (forced) return forced;
  const c = otherModelCache[engine];
  if (c && Date.now() < c.exp) return c.model;
  let model = { openai: 'gpt-4o-mini', claude: 'claude-sonnet-4-5', deepseek: 'deepseek-chat' }[engine];
  try {
    if (engine === 'openai') {
      const r = await fetch('https://api.openai.com/v1/models', { headers: { Authorization: `Bearer ${key}` } });
      if (r.ok) model = pickOpenAIModel(((await r.json()).data || []).map((m) => m.id));
    } else if (engine === 'claude') {
      const r = await fetch('https://api.anthropic.com/v1/models?limit=100', { headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } });
      if (r.ok) model = pickClaudeModel((await r.json()).data || []);
    }
  } catch (e) {}
  otherModelCache[engine] = { model, exp: Date.now() + 6 * 3600 * 1000 };
  return model;
}

/** Conversation (format Gemini) → format ChatGPT / DeepSeek */
export function toOpenAIMessages(contents, system, vision) {
  const msgs = system ? [{ role: 'system', content: system }] : [];
  for (const c of contents) {
    const role = c.role === 'model' ? 'assistant' : 'user';
    const text = c.parts.filter((p) => typeof p.text === 'string').map((p) => p.text).join('\n') || ' ';
    const imgs = c.parts.filter((p) => p.inlineData);
    if (vision && role === 'user' && imgs.length) {
      msgs.push({ role, content: [{ type: 'text', text }, ...imgs.map((p) => ({ type: 'image_url', image_url: { url: `data:${p.inlineData.mimeType};base64,${p.inlineData.data}` } }))] });
    } else msgs.push({ role, content: text });
  }
  return msgs;
}
/** Conversation (format Gemini) → format Claude */
export function toClaudeMessages(contents) {
  const out = [];
  for (const c of contents) {
    const role = c.role === 'model' ? 'assistant' : 'user';
    const blocks = [];
    for (const p of c.parts) {
      if (p.inlineData && /^image\/(png|jpeg|gif|webp)$/.test(p.inlineData.mimeType)) blocks.push({ type: 'image', source: { type: 'base64', media_type: p.inlineData.mimeType, data: p.inlineData.data } });
      else if (typeof p.text === 'string' && p.text) blocks.push({ type: 'text', text: p.text });
    }
    if (!blocks.length) blocks.push({ type: 'text', text: ' ' });
    const prev = out[out.length - 1];
    if (prev && prev.role === role) prev.content.push(...blocks); // Claude exige l'alternance des rôles
    else out.push({ role, content: blocks });
  }
  while (out.length && out[0].role !== 'user') out.shift();
  return out;
}

/** Lance un moteur non-Gemini en streaming ; renvoie la réponse HTTP */
async function callOtherEngine(engine, key, model, contents, system, opts) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs || 25000);
  try {
    if (engine === 'claude') {
      return await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model, system: system || undefined, messages: toClaudeMessages(contents), max_tokens: Math.min(32000, Number(opts.maxTokens) || 16000), stream: true }),
        signal: ctrl.signal,
      });
    }
    const url = engine === 'openai' ? 'https://api.openai.com/v1/chat/completions' : 'https://api.deepseek.com/chat/completions';
    return await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${key}` },
      body: JSON.stringify({ model, messages: toOpenAIMessages(contents, system, engine === 'openai'), stream: true }),
      signal: ctrl.signal,
    });
  } catch (e) {
    if (e.name === 'AbortError') return new Response(JSON.stringify({ error: { message: `${ENGINE_LABELS[engine]} trop lent (délai dépassé)` } }), { status: 504 });
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** Extrait le texte d'un événement de flux ChatGPT / DeepSeek / Claude */
export function otherStreamText(engine, json) {
  if (engine === 'claude') return json?.type === 'content_block_delta' && json.delta?.type === 'text_delta' ? json.delta.text || '' : '';
  return json?.choices?.[0]?.delta?.content || '';
}

/* ---------------- Recherche web propre à BOUA Cloud (Google Actualités, gratuit, sans clé) ---------------- */
const NEWS_LOCALES = { fr: ['fr', 'FR'], es: ['es', 'ES'], en: ['en', 'US'], ar: ['ar', 'EG'] };

function decodeXml(str) {
  return String(str || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .trim();
}

export function parseNewsRss(xml, max = 8) {
  const items = [];
  const re = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = re.exec(xml)) && items.length < max) {
    const block = m[1];
    const pick = (tag) => decodeXml((block.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`)) || [])[1]);
    const link = pick('link');
    if (!/^https?:\/\//.test(link)) continue;
    const date = new Date(pick('pubDate'));
    items.push({
      title: pick('title').slice(0, 300),
      uri: link.slice(0, 2000),
      source: pick('source').slice(0, 120),
      date: isNaN(date) ? '' : date.toISOString().slice(0, 10),
    });
  }
  return items;
}

async function searchNews(query, lang) {
  const [hl, gl] = NEWS_LOCALES[lang] || NEWS_LOCALES.fr;
  // Mots-clés uniquement : « Quand sont les élections générales en Espagne ? » → « élections générales Espagne »
  const STOP = /^(quand|quel|quelle|quels|quelles|qui|que|quoi|comment|pourquoi|où|est|sont|ce|c|qu|les|le|la|l|des|de|du|d|un|une|en|à|au|aux|et|ou|pour|sur|dans|me|moi|dis|donne|peux|tu|vous|est-ce|cuándo|cuando|qué|que|quién|cómo|dónde|son|es|el|los|las|del|de|y|en|para|por|me|dime|when|what|who|how|where|is|are|the|of|in|on|for|and|tell|me|a|an)$/i;
  const words = String(query || '')
    .replace(/[?!¿¡.,;:«»"()]/g, ' ')
    .split(/\s+/)
    .filter((w) => w && !STOP.test(w));
  const q = (words.length >= 2 ? words.join(' ') : String(query || '')).replace(/\s+/g, ' ').trim().slice(0, 200);
  if (!q) return [];
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 6000);
  try {
    const url = `https://news.google.com/rss/search?q=${encodeURIComponent(q)}&hl=${hl}&gl=${gl}&ceid=${gl}:${hl}`;
    const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 (BOUA Cloud)' }, signal: ctrl.signal });
    if (!res.ok) return [];
    return parseNewsRss(await res.text());
  } catch (e) {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/* ---------------- Validation de la requête ---------------- */
function sanitizeContents(contents) {
  if (!Array.isArray(contents) || contents.length === 0 || contents.length > MAX_CONTENTS) throw new Error('Conversation invalide');
  return contents.map((c) => {
    const role = c?.role === 'model' ? 'model' : 'user';
    const parts = (Array.isArray(c?.parts) ? c.parts : []).slice(0, 20).map((p) => {
      if (typeof p?.text === 'string') return { text: p.text.slice(0, 400000) };
      if (p?.inlineData && /^image\/(png|jpeg|webp|gif|heic|heif)$/.test(p.inlineData.mimeType || '') && typeof p.inlineData.data === 'string') {
        return { inlineData: { mimeType: p.inlineData.mimeType, data: p.inlineData.data } };
      }
      return { text: '' };
    });
    return { role, parts: parts.length ? parts : [{ text: '' }] };
  });
}

/* ---------------- Gestionnaire principal ---------------- */
export default async function handler(req) {
  const origin = allowedOrigin(req);
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (req.method === 'GET') {
    // Diagnostic sans secret : https://boua-ia.vercel.app/api/chat
    const keys = [env('GEMINI_API_KEY'), env('GEMINI_API_KEY_2'), env('GEMINI_API_KEY_3'), ...env('GEMINI_API_KEYS').split(',')].map((x) => x.trim()).filter(Boolean);
    const m = keys.length ? await resolveModels(keys[0]) : { text: [], image: [] };
    const ok = engineKeys();
    const moteurs = { gemini: keys.length > 0, chatgpt: Boolean(ok.openai), claude: Boolean(ok.claude), deepseek: Boolean(ok.deepseek) };
    return new Response(JSON.stringify({ service: 'BOUA Cloud', version: 9, moteurs, clesConfigurees: keys.length, modelesTexte: m.text.slice(0, 8), modelesImage: m.image.slice(0, 3), modelesEcartes: [...badModels.entries()].filter(([, t]) => t > Date.now()).map(([n]) => n) }, null, 2), {
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  if (req.method !== 'POST') return jsonError(405, 'Méthode non autorisée', origin);
  if (req.headers.get('origin') && !origin) return jsonError(403, 'Origine non autorisée', '');

  // Clés Gemini du serveur (rotation automatique si une clé atteint son quota)
  const apiKeys = [env('GEMINI_API_KEY'), env('GEMINI_API_KEY_2'), env('GEMINI_API_KEY_3'), ...env('GEMINI_API_KEYS').split(',')]
    .map((k) => k.trim())
    .filter((k, i, arr) => k && arr.indexOf(k) === i);
  const apiKey = apiKeys[0];
  const otherKeys = engineKeys();
  if (!apiKey && !otherKeys.openai && !otherKeys.claude && !otherKeys.deepseek) return jsonError(503, 'BOUA Cloud non configuré : ajoutez GEMINI_API_KEY dans Vercel (Settings → Environment Variables), puis redéployez.', origin);

  // 1. Authentification
  const auth = req.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return jsonError(401, 'Connectez-vous à votre compte BOUA AI pour utiliser BOUA Cloud.', origin);
  let user;
  try {
    user = await verifyFirebaseIdToken(token);
  } catch (e) {
    return jsonError(401, e.message || 'Session invalide', origin);
  }
  const isGuest = user.firebase?.sign_in_provider === 'anonymous';
  const ip = (req.headers.get('x-forwarded-for') || req.headers.get('x-real-ip') || '').split(',')[0].trim();
  if (rateLimited(user.sub, isGuest ? 10 : RATE_LIMIT_PER_MIN) || (ip && rateLimited('ip:' + ip, 40))) {
    return jsonError(
      429,
      isGuest ? 'Limite invité atteinte (10 messages par minute). Créez un compte gratuit pour 20 messages par minute.' : 'Trop de messages en une minute. Patientez quelques secondes.',
      origin
    );
  }

  // 2. Lecture et validation
  const len = Number(req.headers.get('content-length') || 0);
  if (len > MAX_BODY_BYTES) return jsonError(413, 'Message trop volumineux (images trop lourdes ?)', origin);
  let body;
  try {
    const raw = await req.text();
    if (raw.length > MAX_BODY_BYTES) return jsonError(413, 'Message trop volumineux', origin);
    body = JSON.parse(raw);
  } catch (e) {
    return jsonError(400, 'Requête invalide', origin);
  }

  let contents;
  try {
    contents = sanitizeContents(body.contents);
  } catch (e) {
    return jsonError(400, e.message, origin);
  }
  const isImage = body.mode === 'image';
  const system = typeof body.systemInstruction === 'string' ? body.systemInstruction.slice(0, 60000) : '';
  const temperature = Math.min(1.2, Math.max(0, Number(body.temperature) || 0.5));

  // 3. Appel Gemini : pour chaque clé, essaie les modèles dans l'ordre jusqu'à obtenir une réponse
  const wantWeb = Boolean(body.web || body.webSearch || body.search || body.googleSearch) && !isImage;
  const ATTEMPT_TIMEOUT_MS = 20000; // délai max d'attente d'un modèle avant de passer au suivant
  const callOnce = async (key, model, withWeb) => {
    const payload = { contents };
    if (system && !isImage) payload.systemInstruction = { parts: [{ text: system }] };
    payload.generationConfig = isImage
      ? { responseModalities: ['TEXT', 'IMAGE'], ...(body.aspectRatio ? { imageConfig: { aspectRatio: String(body.aspectRatio).slice(0, 8) } } : {}) }
      : { temperature, maxOutputTokens: Math.min(65536, Math.max(1024, Number(body.maxTokens) || 16384)) };
    if (withWeb) payload.tools = [{ google_search: {} }];
    const url = isImage ? `${GEMINI_BASE}/models/${encodeURIComponent(model)}:generateContent` : `${GEMINI_BASE}/models/${encodeURIComponent(model)}:streamGenerateContent?alt=sse`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), isImage ? 90000 : ATTEMPT_TIMEOUT_MS);
    try {
      // SÉCURITÉ : la clé part dans un en-tête, jamais dans l'URL
      return await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key }, body: JSON.stringify(payload), signal: ctrl.signal });
    } catch (e) {
      if (e.name === 'AbortError') return new Response(JSON.stringify({ error: { message: `${model} trop lent (délai dépassé)` } }), { status: 504 });
      throw e;
    } finally {
      clearTimeout(timer);
    }
  };
  const readErr = async (r) => {
    try {
      const j = await r.json();
      return String(j?.error?.message || '').slice(0, 400);
    } catch (e) {
      return '';
    }
  };

  // Recherche web BOUA (indépendante de Gemini) pour les questions d'actualité
  let webResults = [];
  if (!isImage && (body.mustSearch || (wantWeb && body.alwaysSearch))) {
    const lastUser = [...contents].reverse().find((c) => c.role === 'user');
    const userText = String(body.query || lastUser?.parts?.map((p) => p.text || '').join(' ') || '');
    webResults = await searchNews(userText, String(body.lang || 'fr'));
    if (webResults.length && lastUser) {
      const today = new Date().toISOString().slice(0, 10);
      const block =
        `\n\n[RÉSULTATS DE RECHERCHE WEB RÉELS — Google Actualités, consultés le ${today}. Ces informations sont plus récentes et plus fiables que tes connaissances internes : base ta réponse dessus, cite les sources par leur nom et indique les dates.]\n` +
        webResults.map((r, i) => `${i + 1}. ${r.title}${r.source ? ` — ${r.source}` : ''}${r.date ? ` (${r.date})` : ''}`).join('\n');
      lastUser.parts = [...lastUser.parts, { text: block }];
    }
  }

  // Ordre des moteurs : préférence de l'utilisateur, sinon Gemini (gratuit) puis les autres en secours
  const configured = { gemini: apiKeys.length > 0, claude: Boolean(otherKeys.claude), openai: Boolean(otherKeys.openai), deepseek: Boolean(otherKeys.deepseek) };
  const baseOrder = (env('BOUA_ENGINE_ORDER') || 'gemini,claude,openai,deepseek').split(',').map((x) => x.trim().toLowerCase().replace('chatgpt', 'openai')).filter((x) => x in configured);
  const wanted = String(body.engine || 'auto').toLowerCase().replace('chatgpt', 'openai');
  let order = (wanted in configured ? [wanted, ...baseOrder.filter((x) => x !== wanted)] : baseOrder).filter((e) => configured[e]);
  if (body.engineOnly && wanted in configured) order = configured[wanted] ? [wanted] : []; // mode /comparer : un seul moteur
  if (isImage) order = order.filter((e) => e === 'gemini'); // seule la génération d'image Gemini est prise en charge
  if (!order.length) return jsonError(503, isImage ? 'Génération d’image indisponible (aucune clé Gemini).' : `Moteur ${ENGINE_LABELS[wanted] || wanted} non configuré sur le serveur.`, origin);

  let candidates = [];
  if (configured.gemini) {
    const models = await resolveModels(apiKey);
    const allCandidates = (isImage ? models.image : models.text).slice(0, 8);
    const freshCandidates = allCandidates.filter((m) => !isBad(m));
    candidates = freshCandidates.length ? freshCandidates : allCandidates;
  }

  /*
   * TEMPS RÉEL SANS ERREUR 504 : la réponse au navigateur s'ouvre IMMÉDIATEMENT (Vercel exige un début
   * de réponse en moins de 25 s). Les essais se font ensuite dans le flux, avec un signal de vie toutes
   * les 8 s. Une erreur finale est envoyée comme événement : data: {"error":{...}}
   */
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();
  const send = (str) => writer.write(enc.encode(str)).catch(() => {});
  const reasonOf = (status, msg) => {
    if (status === 401 || status === 403) return 'clé refusée';
    if (status === 402 || /insufficient|balance|billing|credit/i.test(msg)) return 'crédit épuisé';
    if (status === 429) return /limit:\s*0\b/.test(msg) ? 'pas de quota gratuit' : 'quota épuisé';
    if (status === 504) return 'trop lent';
    if (status === 404 || /no longer available|not found|not supported|does not exist/i.test(msg)) return 'modèle indisponible';
    return `erreur ${status}`;
  };

  (async () => {
    const ping = setInterval(() => send(': ping\n\n'), 8000);
    await send(': ouverture BOUA Cloud\n\n');
    const tried = [];
    let lastMsg = 'Aucun moteur n’a répondu.';
    const sendMeta = (engine, model, webUsed) =>
      send(
        `data: ${JSON.stringify({
          boua: {
            engine,
            engineLabel: ENGINE_LABELS[engine],
            model,
            webAvailable: webUsed || webResults.length > 0,
            searched: webResults.length > 0,
            sources: webResults.map((r) => ({ uri: r.uri, title: `${r.title}${r.source ? ' — ' + r.source : ''}${r.date ? ' (' + r.date + ')' : ''}` })),
          },
        })}\n\n`
      );

    try {
      for (const engine of order) {
        /* ---------- Gemini : clés × modèles ---------- */
        if (engine === 'gemini') {
          let res = null;
          let model = '';
          let webUsed = false;
          outer: for (let k = 0; k < apiKeys.length; k++) {
            for (const m of candidates) {
              try {
                let r = await callOnce(apiKeys[k], m, wantWeb);
                let preMsg = '';
                if (!r.ok && wantWeb && (r.status === 400 || r.status === 429 || r.status === 504)) {
                  preMsg = await readErr(r);
                  if (!/limit:\s*0\b|no longer available|not found|not supported/i.test(preMsg)) {
                    r = await callOnce(apiKeys[k], m, false); // recherche Google indisponible : on répond sans
                    r.__web = false;
                    preMsg = '';
                  }
                }
                if (r.ok) {
                  res = r;
                  model = m;
                  webUsed = wantWeb && r.__web !== false;
                  break outer;
                }
                lastMsg = preMsg || (await readErr(r)) || `HTTP ${r.status}`;
                const reason = reasonOf(r.status, lastMsg);
                if (reason === 'modèle indisponible') markBad(m, 6 * 3600 * 1000);
                else if (reason === 'pas de quota gratuit') markBad(m, 3600 * 1000);
                else if (reason === 'quota épuisé') markBad(m, 60 * 1000);
                else if (reason === 'trop lent') markBad(m, 10 * 60 * 1000);
                tried.push(`Gemini ${m}${apiKeys.length > 1 ? ` (clé ${k + 1})` : ''} → ${reason}`);
                if (r.status === 400 && reason !== 'modèle indisponible') break outer; // requête refusée : on passe au moteur suivant
                if (r.status === 401 || r.status === 403) break; // clé suivante
              } catch (e) {
                lastMsg = e.message || lastMsg;
              }
            }
          }
          if (!res) continue;
          await send(`: modele ${model}\n\n`);
          await sendMeta('gemini', model, webUsed);
          if (isImage) {
            const data = await res.text();
            await send(`data: ${data.replace(/\n/g, ' ')}\n\n`);
            return;
          }
          const reader = res.body.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            await writer.write(value).catch(() => {});
          }
          return;
        }

        /* ---------- ChatGPT / Claude / DeepSeek ---------- */
        const key = otherKeys[engine];
        let model = '';
        try {
          model = await resolveOtherModel(engine, key);
          const r = await callOtherEngine(engine, key, model, contents, system, { maxTokens: body.maxTokens });
          if (!r.ok) {
            lastMsg = (await readErr(r)) || `HTTP ${r.status}`;
            tried.push(`${ENGINE_LABELS[engine]} ${model} → ${reasonOf(r.status, lastMsg)}`);
            if (r.status === 404) delete otherModelCache[engine];
            continue;
          }
          await send(`: modele ${model}\n\n`);
          await sendMeta(engine, model, false);
          // Conversion du flux vers le format Gemini attendu par le site
          const reader = r.body.getReader();
          const dec = new TextDecoder();
          let buf = '';
          let gotText = false;
          const handle = async (line) => {
            const l = line.replace(/\r$/, '');
            if (!l.startsWith('data:')) return;
            const d = l.slice(5).trim();
            if (!d || d === '[DONE]') return;
            try {
              const j = JSON.parse(d);
              if (j?.type === 'error' || j?.error) {
                lastMsg = j.error?.message || 'Erreur';
                return;
              }
              const t = otherStreamText(engine, j);
              if (t) {
                gotText = true;
                await send(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: t }] } }] })}\n\n`);
              }
            } catch (e) {}
          };
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buf += dec.decode(value, { stream: true });
            let i;
            while ((i = buf.indexOf('\n')) >= 0) {
              await handle(buf.slice(0, i));
              buf = buf.slice(i + 1);
            }
          }
          if (buf) await handle(buf);
          if (gotText) return;
          tried.push(`${ENGINE_LABELS[engine]} ${model} → réponse vide`);
        } catch (e) {
          lastMsg = e.message || lastMsg;
          tried.push(`${ENGINE_LABELS[engine]} ${model} → ${lastMsg.slice(0, 80)}`);
        }
      }

      // Tous les moteurs ont échoué
      const summary = tried.join(' • ');
      console.error('[BOUA Cloud] Échec de tous les moteurs :', summary, '—', lastMsg);
      let message = `Aucun moteur n'a pu répondre. ${summary ? 'Détail : ' + summary + '. ' : ''}Dernier message : ${lastMsg}`;
      if (tried.length && tried.every((t) => /quota/.test(t))) {
        message = `Quotas épuisés sur tous les moteurs pour le moment (${summary}). Réessayez dans une minute.`;
      }
      await send(`data: ${JSON.stringify({ error: { message } })}\n\n`);
    } catch (e) {
      await send(`data: ${JSON.stringify({ error: { message: e.message || 'Erreur BOUA Cloud' } })}\n\n`);
    } finally {
      clearInterval(ping);
      writer.close().catch(() => {});
    }
  })();

  return new Response(readable, {
    status: 200,
    headers: {
      ...corsHeaders(origin),
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store, no-transform',
      'X-Content-Type-Options': 'nosniff',
      'X-Accel-Buffering': 'no',
    },
  });
}
