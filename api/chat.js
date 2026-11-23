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
 *   GEMINI_API_KEY_2 … GEMINI_API_KEY_10 (facultatif) clés de secours : si une clé atteint son quota, la suivante prend le relais
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
let modelCache = { text: [], image: [], video: [], exp: 0 };
// Modèles temporairement écartés (quota nul, retirés…) pour aller directement vers un modèle qui répond
const badModels = new Map(); // nom -> horodatage de fin d'exclusion
// Journal des derniers événements (sans aucun texte des utilisateurs) — visible sur la page de diagnostic
const EVENTS = [];
const logEvent = (ev, info = '') => {
  EVENTS.push({ heure: new Date().toISOString().slice(11, 19), ev, info: String(info).slice(0, 160) });
  if (EVENTS.length > 20) EVENTS.shift();
};
// Modèles qui refusent le réglage de réflexion (thinkingConfig)
const noThinkCfg = new Set();
const isBad = (m) => (badModels.get(m) || 0) > Date.now();
// Dernier modèle ayant répondu : réessayé en premier (réponses plus rapides, moins d'essais inutiles)
const lastGood = { fast: '', quality: '' };
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
  // Vidéo : modèles Veo (méthode predictLongRunning), du plus récent au plus ancien
  const video = models
    .filter((m) => /veo/.test(m.name) && (m.supportedGenerationMethods || []).includes('predictLongRunning'))
    .map((m) => m.name.replace(/^models\//, ''))
    .sort((a, b) => (parseFloat((b.match(/veo-(\d+(?:\.\d+)?)/) || [])[1]) || 0) - (parseFloat((a.match(/veo-(\d+(?:\.\d+)?)/) || [])[1]) || 0));
  const imageList = [...images.filter((n) => !/preview/.test(n)).sort(byVersion), ...images.filter((n) => /preview/.test(n)).sort(byVersion)];
  return { text: [...new Set(text)], image: imageList, video };
}

async function resolveModels(apiKey, force = false) {
  if (!force && modelCache.text.length && Date.now() < modelCache.exp) return modelCache;
  let picked = { text: [], image: [], video: [] };
  try {
    const res = await fetch(`${GEMINI_BASE}/models?pageSize=1000`, { headers: { 'x-goog-api-key': apiKey } });
    if (res.ok) picked = pickModels((await res.json()).models || []);
  } catch (e) {}
  const forcedText = env('GEMINI_MODEL');
  const forcedImage = env('GEMINI_IMAGE_MODEL');
  const text = [...new Set([forcedText, ...picked.text, 'gemini-flash-latest', 'gemini-flash-lite-latest'].filter(Boolean))];
  const image = [...new Set([forcedImage, ...picked.image].filter(Boolean))];
  modelCache = { text, image, video: picked.video || [], exp: Date.now() + 6 * 3600 * 1000 };
  return modelCache;
}

/** Clés Gemini : GEMINI_API_KEY, GEMINI_API_KEY_2 … GEMINI_API_KEY_10, et GEMINI_API_KEYS (séparées par des virgules) */
export function geminiKeys() {
  const names = ['GEMINI_API_KEY', ...Array.from({ length: 9 }, (_, i) => `GEMINI_API_KEY_${i + 2}`)];
  return [...names.map((n) => env(n)), ...env('GEMINI_API_KEYS').split(',')]
    .map((k) => String(k || '').trim())
    .filter((k, i, arr) => k && arr.indexOf(k) === i);
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
const ENGINE_LABELS = { gemini: 'Gemini', openai: 'ChatGPT', claude: 'Claude', deepseek: 'DeepSeek', free: 'Image gratuite' };

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
  const STOP = /^(quand|quel|quelle|quels|quelles|qui|que|quoi|comment|pourquoi|où|est|sont|ce|c|qu|les|le|la|l|des|de|du|d|un|une|en|à|au|aux|et|ou|pour|sur|dans|me|moi|dis|donne|peux|tu|vous|est-ce|cuándo|cuando|qué|que|quién|cómo|dónde|son|es|el|los|las|del|de|y|en|para|por|me|dime|when|what|who|how|where|is|are|the|of|in|on|for|and|tell|me|a|an|explique|explique-moi|expliquer|explique-nous|parle|parle-moi|parlez|raconte|raconte-moi|résume|résume-moi|donne-moi|dis-moi|peux-tu|pouvez-vous|actuelle|actuel|actuels|actuelles|actuellement|aujourd'hui|aujourd’hui|maintenant|stp|svp|merci|bonjour|salut|nous|explícame|explica|háblame|actual|hoy|ahora|explain|current|currently|latest|today|now|please)$/i;
  const words = String(query || '')
    .replace(/[?!¿¡.,;:«»"()]/g, ' ')
    .split(/\s+/)
    .filter((w) => w && !STOP.test(w));
  const q = (words.length >= 2 ? words.join(' ') : String(query || '')).replace(/\s+/g, ' ').trim().slice(0, 200);
  if (!q) return [];
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 6000);
  try {
    const get = async (qq) => {
      const url = `https://news.google.com/rss/search?q=${encodeURIComponent(qq)}&hl=${hl}&gl=${gl}&ceid=${gl}:${hl}`;
      const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 (BOUA Cloud)' }, signal: ctrl.signal });
      return res.ok ? parseNewsRss(await res.text()) : [];
    };
    let out = await get(q);
    // Trop précis ? on réessaie avec les noms propres / mots principaux (« situation Mali » → « Mali »)
    if (!out.length && words.length > 1) {
      const proper = words.filter((w) => /^[A-ZÀ-Ý]/.test(w) && w.length > 2);
      const q2 = (proper.length ? proper : words.slice(-2)).join(' ');
      if (q2 && q2 !== q) out = await get(q2);
    }
    return out;
  } catch (e) {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/** Résultats web (DuckDuckGo, version HTML sans clé) — au mieux, ignoré en cas d'échec */
export function parseDuckHtml(html, max = 6) {
  const out = [];
  const re = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g;
  let m;
  while ((m = re.exec(html)) && out.length < max) {
    let href = decodeXml(m[1]);
    const u = href.match(/[?&]uddg=([^&]+)/);
    if (u) href = decodeURIComponent(u[1]);
    if (href.startsWith('//')) href = 'https:' + href;
    if (!/^https?:\/\//.test(href) || /duckduckgo\.com\/y\.js/.test(href)) continue;
    out.push({ title: decodeXml(m[2]).slice(0, 300), uri: href.slice(0, 2000), snippet: decodeXml(m[3]).slice(0, 500), source: new URL(href).hostname.replace(/^www\./, '') });
  }
  return out;
}

async function timedFetch(url, ms, init = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function searchWeb(query, lang) {
  try {
    const kl = { fr: 'fr-fr', es: 'es-es', en: 'us-en', ar: 'xa-ar' }[lang] || 'fr-fr';
    const r = await timedFetch(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}&kl=${kl}`, 7000, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BOUA-Cloud', Accept: 'text/html' },
    });
    return r.ok ? parseDuckHtml(await r.text()) : [];
  } catch (e) {
    return [];
  }
}

async function searchWikipedia(query, lang) {
  const wl = ['fr', 'es', 'en', 'ar'].includes(lang) ? lang : 'fr';
  try {
    const r = await timedFetch(
      `https://${wl}.wikipedia.org/w/api.php?action=query&generator=search&gsrsearch=${encodeURIComponent(query)}&gsrlimit=2&prop=extracts|info&exintro=1&explaintext=1&exchars=1200&inprop=url&format=json&origin=*`,
      6000,
      { headers: { 'User-Agent': 'BOUA-Cloud/1.0 (assistant IA)' } }
    );
    if (!r.ok) return [];
    const pages = Object.values((await r.json())?.query?.pages || {});
    return pages
      .filter((pg) => pg.extract && pg.fullurl)
      .map((pg) => ({ title: `${pg.title} — Wikipédia`, uri: pg.fullurl, snippet: pg.extract.slice(0, 1200), source: 'Wikipédia' }));
  } catch (e) {
    return [];
  }
}

// Seul le contenu à risque ÉLEVÉ est bloqué : les sujets d'actualité (guerre, terrorisme, politique, élections) restent traités
const SAFETY_SETTINGS = ['HARM_CATEGORY_HARASSMENT', 'HARM_CATEGORY_HATE_SPEECH', 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'HARM_CATEGORY_DANGEROUS_CONTENT', 'HARM_CATEGORY_CIVIC_INTEGRITY'].map((category) => ({ category, threshold: 'BLOCK_ONLY_HIGH' }));
const BLOCK_RE = /SAFETY|PROHIBITED|BLOCKLIST|SPII|RECITATION|OTHER|LANGUAGE/;

/* ---------------- DONNÉES EN TEMPS RÉEL (gratuites, sans clé) ---------------- */
// Détection rapide : on n'interroge l'IA (extraction) que si ces mots sont présents
export const REALTIME_RE = new RegExp(String.raw`(m[ée]t[ée]o|temps qu.il fait|quel temps|temp[ée]rature (à|a|en|au|de|aujourd)|pr[ée]visions? (météo|du temps|pour)|\bil (pleut|neige)\b|\bpluie\b|\bclima\b|qu[ée] tiempo|el tiempo (en|hoy|mañana|para)|\blluvia|weather|forecast|طقس|taux de change|tipo de cambio|exchange rate|cours (de l.|du) ?(euro|dollar|franc|dirham|yen|livre)|\bdevises?\b|\bdivisas?\b|currency|(convertir|conversion|combien (font|fait|vaut|valent)|cu[áa]nto (es|son|vale)n?|how much is)[^.?!
]{0,40}(€|\$|euros?|dollars?|fcfa|f ?cfa|cfa|xof|xaf|usd|eur|gbp|dirhams?|yens?|yuans?|livres? sterling|francs? (cfa|suisses?)|pesos?|nairas?|cedis?)\b|\b\d[\d\s.,]*\s?(€|\$|euros?|dollars?|fcfa|f ?cfa|cfa|xof|xaf|usd|eur|gbp|dirhams?|yens?|yuans?|livres? sterling|francs? (cfa|suisses?)|pesos?|nairas?|cedis?)\s+(en|à|a|in|to|vers)\s+(€|\$|euros?|dollars?|fcfa|f ?cfa|cfa|xof|xaf|usd|eur|gbp|dirhams?|yens?|yuans?|livres? sterling|francs? (cfa|suisses?)|pesos?|nairas?|cedis?)\b|quelle heure|qu.elle heure est|heure (actuelle|locale)|qu[ée] hora|what time|fuseau horaire)`, 'i');

const WMO = { 0: 'ciel dégagé', 1: 'plutôt dégagé', 2: 'partiellement nuageux', 3: 'couvert', 45: 'brouillard', 48: 'brouillard givrant', 51: 'bruine légère', 53: 'bruine', 55: 'bruine forte', 61: 'pluie faible', 63: 'pluie', 65: 'pluie forte', 66: 'pluie verglaçante', 67: 'pluie verglaçante forte', 71: 'neige faible', 73: 'neige', 75: 'neige forte', 77: 'grains de neige', 80: 'averses faibles', 81: 'averses', 82: 'averses violentes', 85: 'averses de neige', 86: 'fortes averses de neige', 95: 'orage', 96: 'orage avec grêle', 99: 'orage violent avec grêle' };
// Monnaies à parité fixe avec l'euro (non publiées par la BCE)
const EUR_PEGS = { XOF: 655.957, XAF: 655.957, KMF: 491.96775 };

async function geocode(city, lang) {
  const r = await timedFetch(`https://geocoding-api.open-meteo.com/v1/search?name=${encodeURIComponent(city)}&count=1&language=${['fr', 'es', 'en', 'ar'].includes(lang) ? lang : 'fr'}&format=json`, 6000);
  if (!r.ok) return null;
  const g = (await r.json())?.results?.[0];
  return g ? { name: g.name, country: g.country || '', lat: g.latitude, lon: g.longitude, tz: g.timezone } : null;
}

export async function weatherFor(city, lang) {
  const g = await geocode(city, lang);
  if (!g) return null;
  const r = await timedFetch(
    `https://api.open-meteo.com/v1/forecast?latitude=${g.lat}&longitude=${g.lon}&current=temperature_2m,apparent_temperature,relative_humidity_2m,wind_speed_10m,weather_code&daily=weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max&timezone=auto&forecast_days=4`,
    7000
  );
  if (!r.ok) return null;
  const d = await r.json();
  const c = d.current || {};
  const days = (d.daily?.time || []).map((t, i) => `${t} : ${WMO[d.daily.weather_code[i]] || '—'}, ${Math.round(d.daily.temperature_2m_min[i])}°C / ${Math.round(d.daily.temperature_2m_max[i])}°C, risque de pluie ${d.daily.precipitation_probability_max?.[i] ?? '?'} %`);
  return {
    text: `MÉTÉO ${g.name} (${g.country}) — relevé de ${c.time || 'maintenant'} (heure locale) : ${WMO[c.weather_code] || '—'}, ${c.temperature_2m} °C (ressenti ${c.apparent_temperature} °C), humidité ${c.relative_humidity_2m} %, vent ${c.wind_speed_10m} km/h.\nPrévisions :\n- ${days.join('\n- ')}`,
    source: { uri: `https://open-meteo.com/en/docs#latitude=${g.lat}&longitude=${g.lon}`, title: `Météo ${g.name} — Open-Meteo (${(c.time || '').slice(0, 10)})` },
  };
}

export async function currencyFor(from, to, amount) {
  from = String(from || 'EUR').toUpperCase().slice(0, 3);
  to = String(to || 'USD').toUpperCase().slice(0, 3);
  const amt = Number(amount) > 0 ? Number(amount) : 1;
  // Conversion via l'euro pour gérer les monnaies à parité fixe (FCFA…)
  const toEurRate = async (code) => {
    if (code === 'EUR') return { rate: 1, date: '' };
    if (EUR_PEGS[code]) return { rate: EUR_PEGS[code], date: 'parité fixe' };
    const r = await timedFetch(`https://api.frankfurter.app/latest?from=EUR&to=${code}`, 6000);
    if (!r.ok) return null;
    const j = await r.json();
    return j?.rates?.[code] ? { rate: j.rates[code], date: j.date } : null;
  };
  const [a, b] = await Promise.all([toEurRate(from), toEurRate(to)]);
  if (!a || !b) return null;
  const rate = b.rate / a.rate;
  const date = a.date && a.date !== 'parité fixe' ? a.date : b.date;
  return {
    text: `TAUX DE CHANGE (Banque centrale européenne${EUR_PEGS[from] || EUR_PEGS[to] ? ' + parité fixe FCFA/euro' : ''}, ${date}) : 1 ${from} = ${rate.toFixed(6)} ${to} ; ${amt} ${from} = ${(amt * rate).toFixed(2)} ${to}.`,
    source: { uri: 'https://www.ecb.europa.eu/stats/policy_and_exchange_rates/euro_reference_exchange_rates/html/index.fr.html', title: `Taux de change BCE (${date})` },
  };
}

export async function timeFor(city, lang) {
  const g = await geocode(city, lang);
  if (!g?.tz) return null;
  const now = new Date().toLocaleString('fr-FR', { timeZone: g.tz, weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  return { text: `HEURE LOCALE à ${g.name} (${g.country}, fuseau ${g.tz}) : ${now}.`, source: null };
}

const CURRENCY_NAMES = [
  [/francs? suisses?|\bchf\b/i, 'CHF'], [/f\s?cfa|franc?s? cfa|\bcfa\b|\bxof\b/i, 'XOF'], [/\bxaf\b/i, 'XAF'], [/livres? sterling|\bgbp\b|£/i, 'GBP'],
  [/euros?|\beur\b|€/i, 'EUR'], [/dollars? canadiens?|\bcad\b/i, 'CAD'], [/dollars?|\busd\b|\$/i, 'USD'], [/dirhams?|\bmad\b/i, 'MAD'], [/\byens?\b|\bjpy\b/i, 'JPY'],
  [/yuans?|\bcny\b|renminbi/i, 'CNY'], [/nairas?|\bngn\b/i, 'NGN'], [/cedis?|\bghs\b/i, 'GHS'], [/dinars? alg[ée]riens?|\bdzd\b/i, 'DZD'], [/dinars? tunisiens?|\btnd\b/i, 'TND'],
  [/roupies?|\binr\b/i, 'INR'], [/reals?|\bbrl\b/i, 'BRL'], [/pesos? mexicains?|\bmxn\b/i, 'MXN'],
];
const curCode = (t) => (CURRENCY_NAMES.find(([re]) => re.test(t)) || [])[1] || '';
const PLACE_STOP = /\s+(?:aujourd.hui|demain|ce\s|cette|cet\s|maintenant|actuellement|en ce moment|today|tomorrow|now|right now|this|hoy|mañana|ahora|esta|este|svp|s'il)\b.*$/i;
const cleanPlace = (p) => String(p || '').replace(/[?!.,;:«»"]+.*$/, '').replace(PLACE_STOP, '').trim().slice(0, 60);

/** Lecture instantanée de la question (sans appel IA) : météo, heure, conversion */
export function quickRealtimeIntents(q) {
  const out = { meteo: [], devise: null, heure: [] };
  if (/(po[èe]me|histoire|chanson|conte|r[ée]dige|[ée]cris|code|script|fonction|programme)/i.test(q)) return null; // création, pas une demande de données
  const w =
    q.match(/(?:m[ée]t[ée]o|temps|temp[ée]rature|pleut|pluie|neige|weather|forecast|tiempo|clima|lluvia|llueve)[^?!]*?(?:^|\s)(?:à|a|au|aux|en|sur|pour|in|at|for|para|de)\s+([^?!]{2,60})/i) ||
    q.match(/(?:m[ée]t[ée]o|weather|tiempo|clima)\s+([^?!\s][^?!]{1,40})$/i);
  if (w && !/^(fait|il|libre|pass|r[ée]el|aujourd|demain)/i.test(cleanPlace(w[1])) && cleanPlace(w[1])) out.meteo.push(cleanPlace(w[1]));
  const h = q.match(/(?:quelle heure|qu.elle heure|heure (?:actuelle|locale)|qu[ée] hora|what time)[^?!]*?(?:^|\s)(?:à|a|au|en|in|at|de)\s+([^?!]{2,60})/i);
  if (h) out.heure.push(cleanPlace(h[1]));
  const c = q.match(/(\d[\d\s.,]*)?\s*([a-zà-ÿ$€£ ]{1,25}?)\s+(?:en|à|a|in|to|vers|contre|=)\s+([a-zà-ÿ$€£ ]{1,25})/i);
  if (c && /(convert|conversion|combien|cu[áa]nto|how much|taux|change|cambio|vaut|valent|\d)/i.test(q)) {
    const from = curCode(c[2]);
    const to = curCode(c[3]);
    if (from && to && from !== to) out.devise = { de: from, vers: to, montant: c[1] ? Number(String(c[1]).replace(/\s/g, '').replace(',', '.')) || 1 : 1 };
  }
  if (!out.devise && /(taux de change|tipo de cambio|exchange rate|cours (?:de l.|du))/i.test(q)) {
    const codes = [...new Set(CURRENCY_NAMES.flatMap(([re, code]) => (re.test(q) ? [code] : [])))];
    if (codes.length >= 2) out.devise = { de: codes[0], vers: codes[1], montant: 1 };
    else if (codes.length === 1) out.devise = codes[0] === 'EUR' ? { de: 'EUR', vers: 'USD', montant: 1 } : { de: codes[0], vers: 'EUR', montant: 1 };
  }
  return out.meteo.length || out.heure.length || out.devise ? out : null;
}

/** L'IA (modèle rapide) extrait les demandes de données en temps réel de la question */
async function extractRealtimeIntents(question, apiKeys, candidates) {
  const prompt = `Analyse cette question et réponds UNIQUEMENT en JSON : {"meteo":["ville",...],"devise":{"de":"EUR","vers":"USD","montant":1} ou null,"heure":["ville",...]}. Codes ISO 4217 pour les devises (FCFA = XOF). Listes vides si non demandé. Question : « ${question} »`;
  const lite = [...candidates.filter((m) => /lite/.test(m)), ...candidates.filter((m) => !/lite/.test(m))].slice(0, 2);
  for (const key of apiKeys.slice(0, 1)) {
    for (const m of lite) {
      try {
        const r = await timedFetch(`${GEMINI_BASE}/models/${encodeURIComponent(m)}:generateContent`, 3500, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
          body: JSON.stringify({ contents: [{ role: 'user', parts: [{ text: prompt }] }], generationConfig: { temperature: 0, maxOutputTokens: 200, responseMimeType: 'application/json' } }),
        });
        if (!r.ok) continue;
        const t = ((await r.json())?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('');
        return JSON.parse((t.match(/\{[\s\S]*\}/) || ['{}'])[0]);
      } catch (e) {}
    }
  }
  return null;
}

export async function fetchRealtimeData(intents, lang) {
  if (!intents) return [];
  const jobs = [];
  for (const c of (Array.isArray(intents.meteo) ? intents.meteo : []).slice(0, 3)) if (typeof c === 'string' && c.trim()) jobs.push(weatherFor(c.trim().slice(0, 80), lang).catch(() => null));
  const dv = intents.devise;
  if (dv && typeof dv === 'object' && /^[A-Za-z]{3}$/.test(dv.de || '') && /^[A-Za-z]{3}$/.test(dv.vers || '')) jobs.push(currencyFor(dv.de, dv.vers, dv.montant).catch(() => null));
  for (const c of (Array.isArray(intents.heure) ? intents.heure : []).slice(0, 3)) if (typeof c === 'string' && c.trim()) jobs.push(timeFor(c.trim().slice(0, 80), lang).catch(() => null));
  return (await Promise.all(jobs)).filter(Boolean);
}

/** Image gratuite sans clé (Pollinations) — renvoie { mimeType, data(base64) } ou null */
async function freeImage(prompt, aspectRatio, seed) {
  const dims = { '1:1': [1024, 1024], '16:9': [1280, 720], '9:16': [720, 1280], '4:3': [1024, 768] }[aspectRatio] || [1024, 1024];
  const url = `https://image.pollinations.ai/prompt/${encodeURIComponent(String(prompt).slice(0, 800))}?width=${dims[0]}&height=${dims[1]}&nologo=true&safe=true&seed=${seed || Math.floor(Math.random() * 1e6)}`;
  try {
    const r = await timedFetch(url, 70000, { headers: { 'User-Agent': 'BOUA-Cloud/1.0' } });
    const type = (r.headers.get('content-type') || '').split(';')[0];
    if (!r.ok || !/^image\/(png|jpeg|webp)$/.test(type)) return null;
    const buf = new Uint8Array(await r.arrayBuffer());
    if (buf.length < 2000 || buf.length > 6 * 1024 * 1024) return null;
    let bin = '';
    for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    return { mimeType: type, data: btoa(bin) };
  } catch (e) {
    return null;
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
  const startedAt = Date.now();
  const origin = allowedOrigin(req);
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
  if (req.method === 'GET') {
    // Diagnostic sans secret : https://boua-ia.vercel.app/api/chat
    const keys = geminiKeys();
    const m = keys.length ? await resolveModels(keys[0]) : { text: [], image: [] };
    const ok = engineKeys();
    const moteurs = { gemini: keys.length > 0, chatgpt: Boolean(ok.openai), claude: Boolean(ok.claude), deepseek: Boolean(ok.deepseek) };
    return new Response(JSON.stringify({ service: 'BOUA Cloud', version: 20, moteurs, clesConfigurees: keys.length, modelesTexte: m.text.slice(0, 8), modelesImage: m.image.slice(0, 3), modelesVideo: (m.video || []).slice(0, 3), modelesEcartes: [...badModels.entries()].filter(([, t]) => t > Date.now()).map(([n]) => n), derniersEvenements: EVENTS.slice(-15) }, null, 2), {
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  if (req.method !== 'POST') return jsonError(405, 'Méthode non autorisée', origin);
  if (req.headers.get('origin') && !origin) return jsonError(403, 'Origine non autorisée', '');

  // Clés Gemini du serveur (rotation automatique si une clé atteint son quota)
  const apiKeys = geminiKeys();
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

  /* ---------- Transcription vocale (conversation vocale sur Android / navigateurs sans reconnaissance) ---------- */
  if (body.mode === 'transcribe') {
    const json = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders(origin) } });
    const mime = String(body.audio?.mimeType || '').split(';')[0].toLowerCase();
    const data = String(body.audio?.data || '');
    if (!/^audio\/(webm|ogg|mp4|mpeg|wav|x-wav|aac|m4a|3gpp|flac)$/.test(mime) || !data || data.length > 6_000_000 || !/^[A-Za-z0-9+/=]+$/.test(data)) return jsonError(400, 'Audio invalide', origin);
    if (!apiKeys.length) return jsonError(503, 'Transcription indisponible : aucune clé Gemini configurée.', origin);
    const lang = { fr: 'français', es: 'espagnol', en: 'anglais', ar: 'arabe' }[String(body.lang || 'fr')] || 'français';
    const models = await resolveModels(apiKey);
    const list = [...models.text.filter((m) => /flash/.test(m) && !isBad(m))].slice(0, 3);
    for (const key of apiKeys.slice(0, 4)) {
      for (const m of list) {
        try {
          const r = await timedFetch(`${GEMINI_BASE}/models/${encodeURIComponent(m)}:generateContent`, 15000, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
            body: JSON.stringify({
              contents: [{ role: 'user', parts: [{ inlineData: { mimeType: mime, data } }, { text: `Transcris exactement ce que dit la personne (langue probable : ${lang}). Réponds uniquement avec la transcription, sans commentaire. Si on n'entend aucune parole, réponds une chaîne vide.` }] }],
              generationConfig: { temperature: 0, maxOutputTokens: 1024 },
            }),
          });
          if (r.status === 429 || r.status === 403) break; // clé suivante
          if (!r.ok) continue;
          const t = ((await r.json())?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('').trim();
          return json({ text: t.slice(0, 4000), model: m });
        } catch (e) {}
      }
    }
    return jsonError(502, 'Transcription impossible pour le moment. Réessayez.', origin);
  }

  /* ---------- Vidéo réaliste (Veo) : nécessite une clé Google ayant accès à Veo ---------- */
  if (body.mode === 'video-start' || body.mode === 'video-status' || body.mode === 'video-file') {
    if (!apiKeys.length) return jsonError(503, 'Vidéo réaliste indisponible : aucune clé Gemini configurée.', origin);
    const json = (o, st = 200) => new Response(JSON.stringify(o), { status: st, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...corsHeaders(origin) } });
    const keyIdx = Math.min(apiKeys.length - 1, Math.max(0, Number(body.keyIndex) || 0));
    const errText = async (r) => {
      try {
        return String((await r.json())?.error?.message || '').slice(0, 300);
      } catch (e) {
        return '';
      }
    };

    if (body.mode === 'video-start') {
      const prompt = String(body.prompt || '').trim().slice(0, 1500);
      if (!prompt) return jsonError(400, 'Description de la vidéo manquante.', origin);
      const vids = (await resolveModels(apiKey)).video || [];
      if (!vids.length) {
        return jsonError(403, 'Vidéo réaliste (Veo) non disponible avec vos clés Google : cette fonction demande en général l’offre payante de Google AI Studio. Le Studio Vidéo crée à la place une vidéo animée avec des images IA.', origin);
      }
      let last = '';
      for (let k = 0; k < apiKeys.length; k++) {
        for (const vm of vids.slice(0, 3)) {
          const r = await timedFetch(`${GEMINI_BASE}/models/${encodeURIComponent(vm)}:predictLongRunning`, 20000, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKeys[k] },
            body: JSON.stringify({ instances: [{ prompt }], parameters: { aspectRatio: body.aspectRatio === '9:16' ? '9:16' : '16:9' } }),
          }).catch((e) => null);
          if (r && r.ok) {
            const op = await r.json();
            if (op?.name) return json({ operation: op.name, keyIndex: k, model: vm });
          }
          last = r ? (await errText(r)) || `HTTP ${r.status}` : 'délai dépassé';
        }
      }
      return jsonError(402, `Veo a refusé la génération (souvent : offre payante requise ou quota épuisé). Détail : ${last}`, origin);
    }

    const op = String(body.operation || '');
    if (!/^models\/[\w.-]+\/operations\/[\w-]+$/.test(op)) return jsonError(400, 'Opération vidéo invalide.', origin);
    const st = await timedFetch(`${GEMINI_BASE}/${op}`, 15000, { headers: { 'x-goog-api-key': apiKeys[keyIdx] } }).catch(() => null);
    if (!st || !st.ok) return jsonError(502, 'Suivi de la vidéo impossible pour le moment.', origin);
    const data = await st.json();
    if (data.error) return jsonError(502, `Génération vidéo échouée : ${String(data.error.message || '').slice(0, 300)}`, origin);
    if (!data.done) return json({ done: false });
    const resp = data.response || {};
    const uri = resp.generateVideoResponse?.generatedSamples?.[0]?.video?.uri || resp.generatedVideos?.[0]?.video?.uri || resp.videos?.[0]?.uri || '';
    if (!uri) return jsonError(502, 'Vidéo terminée mais introuvable (contenu peut-être filtré par Google).', origin);
    if (body.mode === 'video-status') return json({ done: true });
    // SÉCURITÉ : téléchargement uniquement depuis les serveurs Google, avec la clé côté serveur
    if (!/^https:\/\/generativelanguage\.googleapis\.com\//.test(uri)) return jsonError(400, 'Adresse vidéo non autorisée.', origin);
    const file = await fetch(uri, { headers: { 'x-goog-api-key': apiKeys[keyIdx] }, redirect: 'follow' });
    if (!file.ok) return jsonError(502, 'Téléchargement de la vidéo impossible.', origin);
    return new Response(file.body, { status: 200, headers: { 'Content-Type': 'video/mp4', 'Cache-Control': 'no-store', ...corsHeaders(origin) } });
  }

  let contents;
  let pristineContents;
  try {
    contents = sanitizeContents(body.contents);
    pristineContents = JSON.parse(JSON.stringify(contents));
  } catch (e) {
    return jsonError(400, e.message, origin);
  }
  const isImage = body.mode === 'image';
  const speed = body.speed === 'fast' ? 'fast' : 'quality';
  const system = typeof body.systemInstruction === 'string' ? body.systemInstruction.slice(0, 60000) : '';
  const temperature = Math.min(1.2, Math.max(0, Number(body.temperature) || 0.5));

  // 3. Appel Gemini : pour chaque clé, essaie les modèles dans l'ordre jusqu'à obtenir une réponse
  const wantWeb = Boolean(body.web || body.webSearch || body.search || body.googleSearch) && !isImage;
  const ATTEMPT_TIMEOUT_MS = 12000; // délai max d'attente d'un modèle avant de passer au suivant
  const callOnce = async (key, model, withWeb, override) => {
    const payload = { contents: override || contents };
    if (system && !isImage) payload.systemInstruction = { parts: [{ text: system }] };
    payload.generationConfig = isImage
      ? { responseModalities: ['TEXT', 'IMAGE'], ...(body.aspectRatio ? { imageConfig: { aspectRatio: String(body.aspectRatio).slice(0, 8) } } : {}) }
      : {
          temperature,
          maxOutputTokens: Math.min(65536, Math.max(1024, Number(body.maxTokens) || (speed === 'fast' ? 16384 : 32768))),
          ...(/gemini-3|latest/.test(model) && !noThinkCfg.has(model) ? { thinkingConfig: { thinkingLevel: speed === 'fast' || override ? 'low' : 'medium' } } : {}),
        };
    if (!isImage) payload.safetySettings = SAFETY_SETTINGS; // actualité, politique, conflits : informer sans bloquer
    if (withWeb) payload.tools = [{ google_search: {} }];
    const url = isImage ? `${GEMINI_BASE}/models/${encodeURIComponent(model)}:generateContent` : `${GEMINI_BASE}/models/${encodeURIComponent(model)}:streamGenerateContent?alt=sse`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), isImage ? 90000 : ATTEMPT_TIMEOUT_MS);
    try {
      // SÉCURITÉ : la clé part dans un en-tête, jamais dans l'URL
      let res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key }, body: JSON.stringify(payload), signal: ctrl.signal });
      if (res.status === 400 && payload.generationConfig?.thinkingConfig) {
        const msg = await res.clone().text().catch(() => '');
        if (/thinking/i.test(msg)) {
          noThinkCfg.add(model); // ce modèle n'accepte pas le réglage : on le retire et on relance
          logEvent('reglage-reflexion-refuse', model);
          delete payload.generationConfig.thinkingConfig;
          res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key }, body: JSON.stringify(payload), signal: ctrl.signal });
        }
      }
      return res;
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
  if (isImage) order = body.fast ? [] : order.filter((e) => e === 'gemini'); // images : Gemini puis service gratuit
  if (!order.length && !isImage) return jsonError(503, `Moteur ${ENGINE_LABELS[wanted] || wanted} non configuré sur le serveur.`, origin);

  let candidates = [];
  if (configured.gemini) {
    const models = await resolveModels(apiKey);
    const allCandidates = (isImage ? models.image : models.text).slice(0, 8);
    const freshCandidates = allCandidates.filter((m) => !isBad(m));
    candidates = freshCandidates.length ? freshCandidates : allCandidates;
    if (!isImage) {
      // VITESSE : questions simples → modèles « Lite » d'abord ; puis le dernier modèle qui a fonctionné en tête
      if (speed === 'fast') candidates = [...candidates.filter((m) => /lite/.test(m)), ...candidates.filter((m) => !/lite/.test(m))];
      const good = lastGood[speed];
      if (good && candidates.includes(good)) candidates = [good, ...candidates.filter((m) => m !== good)];
    }
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
      /* ---------- Données en temps réel : météo, devises, heure (chiffres exacts + sources) ---------- */
      let realtimeHit = false;
      if (!isImage && apiKeys.length && candidates.length) {
        const lastUserRt = [...contents].reverse().find((c) => c.role === 'user');
        const q = String(body.query || lastUserRt?.parts?.map((p) => p.text || '').join(' ') || '').slice(0, 500);
        if (REALTIME_RE.test(q)) {
          await send(`data: ${JSON.stringify({ boua: { progress: 'Consultation des données en temps réel…' } })}\n\n`);
          // Limite stricte : jamais plus de 5 s d'attente avant que la réponse commence
          const lang = String(body.lang || 'fr');
          const quick = quickRealtimeIntents(q);
          const data = await Promise.race([
            (async () => {
              // 1) lecture instantanée ; 2) si rien de trouvé, l'IA analyse la question
              let d = quick ? await fetchRealtimeData(quick, lang) : [];
              if (!d.length) d = await fetchRealtimeData(await extractRealtimeIntents(q, apiKeys, candidates), lang);
              return d;
            })(),
            new Promise((r) => setTimeout(() => r([]), 6000)),
          ]).catch(() => []);
          if (data.length && lastUserRt) {
            realtimeHit = true;
            // Les chiffres exacts remplacent les titres d'actualité (souvent anciens) : réponse plus juste et plus rapide
            webResults = [];
            lastUserRt.parts = [
              ...lastUserRt.parts.filter((p) => !String(p.text || '').startsWith('\n\n[RÉSULTATS DE RECHERCHE WEB RÉELS')),
              { text: `\n\n[DONNÉES EN TEMPS RÉEL — valeurs exactes obtenues à l'instant. Utilise CES chiffres (n'en invente aucun) et cite la source :]\n${data.map((d) => d.text).join('\n\n')}` },
            ];
            for (const d of data) if (d.source && !webResults.some((w) => w.uri === d.source.uri)) webResults.unshift({ ...d.source, source: '' });
          }
        }
      }

      /* ---------- Recherche approfondie : plan → recherches multi-sources → rapport cité ---------- */
      if (body.deep && !isImage) {
        const lastUser = [...contents].reverse().find((c) => c.role === 'user');
        const question = String(body.query || lastUser?.parts?.map((p) => p.text || '').join(' ') || '').slice(0, 500);
        const lang = String(body.lang || 'fr');
        await send(`data: ${JSON.stringify({ boua: { progress: 'Préparation du plan de recherche…' } })}\n\n`);
        let subQueries = [];
        if (apiKeys.length && candidates.length) {
          const planPrompt = `Découpe cette demande en 3 à 5 requêtes de recherche web courtes et complémentaires (mots-clés, dans la langue la plus pertinente). Date du jour : ${new Date().toISOString().slice(0, 10)}. Demande : « ${question} ». Réponds uniquement par un tableau JSON de chaînes.`;
          outerPlan: for (const key of apiKeys.slice(0, 2)) {
            for (const m of candidates.slice(0, 4)) {
              try {
                const r = await timedFetch(`${GEMINI_BASE}/models/${encodeURIComponent(m)}:generateContent`, 15000, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
                  body: JSON.stringify({ contents: [{ role: 'user', parts: [{ text: planPrompt }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 400 } }),
                });
                if (!r.ok) continue;
                const t = ((await r.json())?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('');
                const arr = JSON.parse((t.match(/\[[\s\S]*\]/) || ['[]'])[0]);
                subQueries = arr.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim().slice(0, 150)).slice(0, 5);
                if (subQueries.length) break outerPlan;
              } catch (e) {}
            }
          }
        }
        if (!subQueries.length) subQueries = [question.slice(0, 150)];
        await send(`data: ${JSON.stringify({ boua: { progress: `Recherche en cours : ${subQueries.join(' · ')}` } })}\n\n`);
        const batches = await Promise.all(
          subQueries.map(async (q, i) => {
            const [news, web, wiki] = await Promise.all([searchNews(q, lang), searchWeb(q, lang), i < 2 ? searchWikipedia(q, lang) : Promise.resolve([])]);
            return [...news.slice(0, 4), ...web.slice(0, 4), ...wiki];
          })
        );
        const seenUri = new Set(webResults.map((r) => r.uri));
        for (const r of batches.flat()) {
          if (r && r.uri && !seenUri.has(r.uri) && webResults.length < 24) {
            seenUri.add(r.uri);
            webResults.push(r);
          }
        }
        await send(`data: ${JSON.stringify({ boua: { progress: `${webResults.length} sources trouvées — rédaction du rapport…` } })}\n\n`);
        if (lastUser && webResults.length) {
          const today = new Date().toISOString().slice(0, 10);
          const block =
            `\n\n[RECHERCHE APPROFONDIE — ${webResults.length} sources réelles consultées le ${today}. Rédige un rapport complet et structuré (résumé, analyse détaillée par thème, points de vigilance, conclusion). Cite chaque affirmation avec le numéro de la source entre crochets, ex. [3]. Signale les contradictions entre sources. Termine par une section « Sources » listant les numéros utilisés.]\n` +
            webResults
              .map((r, i) => `[${i + 1}] ${r.title}${r.source ? ` — ${r.source}` : ''}${r.date ? ` (${r.date})` : ''}${r.snippet ? `\n    ${r.snippet}` : ''}`)
              .join('\n');
          lastUser.parts = [...lastUser.parts, { text: block }];
        }
      }

      /** Transmet un flux Gemini ; ne commence qu'au 1er texte réel. Retourne 'ok', 'bloqué (…)' ou 'réponse vide' */
      const pipeGemini = async (r, m, webUsed, cont = false) => {
        const reader = r.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        let started = cont; // en continuation, la méta a déjà été envoyée
        let gotText = false;
        let midBlock = '';
        let sofar = '';
        let finished = false; // finishReason reçu (sinon : flux interrompu)
        let streamErr = '';
        let lastFinish = '';
        let block = '';
        const pending = [];
        const handle = async (line) => {
          const l = line.replace(/\r$/, '');
          if (!l.startsWith('data:')) return;
          const d = l.slice(5).trim();
          if (!d) return;
          let j;
          try {
            j = JSON.parse(d);
          } catch (e) {
            return;
          }
          if (j?.error && !started) {
            streamErr = `${j.error.code || ''} ${j.error.status || ''} ${String(j.error.message || '').slice(0, 80)}`.trim();
            return;
          }
          const cand = j?.candidates?.[0];
          if (cand?.finishReason) lastFinish = cand.finishReason;
          const hasText = (cand?.content?.parts || []).some((p) => p.text && !p.thought && p.text.trim());
          if (hasText) {
            gotText = true;
            sofar += cand.content.parts.filter((p) => p.text && !p.thought).map((p) => p.text).join('');
          }
          if (cand?.finishReason) finished = true;
          // Coupure en pleine réponse (filtre ou limite de longueur) : on ne transmet pas la fin de flux, on complétera ensuite
          if ((started || hasText) && cand?.finishReason && (BLOCK_RE.test(cand.finishReason) || cand.finishReason === 'MAX_TOKENS')) {
            midBlock = cand.finishReason;
            if (!hasText && cand.finishReason !== 'MAX_TOKENS') block = cand.finishReason;
            if (hasText) {
              const textOnly = { candidates: [{ content: { role: 'model', parts: cand.content.parts.filter((p) => p.text && !p.thought) } }] };
              if (!started) {
                started = true;
                await send(`: modele ${m}\n\n`);
                await sendMeta('gemini', m, webUsed);
              }
              await send(`data: ${JSON.stringify(textOnly)}\n\n`);
            }
            return;
          }
          if (j?.promptFeedback?.blockReason) block = j.promptFeedback.blockReason;
          if (!started && cand?.finishReason && BLOCK_RE.test(cand.finishReason) && !hasText) block = cand.finishReason;
          if (!started && !hasText) {
            pending.push(d);
            return;
          }
          if (!started) {
            started = true;
            await send(`: modele ${m}\n\n`);
            await sendMeta('gemini', m, webUsed);
            for (const p of pending) await send(`data: ${p}\n\n`);
          }
          await send(`data: ${d}\n\n`);
        };
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let k;
          while ((k = buf.indexOf('\n')) >= 0) {
            await handle(buf.slice(0, k));
            buf = buf.slice(k + 1);
          }
        }
        if (buf) await handle(buf);
        if (midBlock && gotText) return { cut: midBlock, sofar };
        if (gotText && !finished) return { cut: 'INTERRUPTED', sofar }; // connexion Google coupée en cours de route
        if (cont) return gotText ? 'ok' : block ? `suite bloquée (${block})` : 'suite vide';
        if (started) return 'ok';
        if (block) return `réponse bloquée par le filtre Google (${block})`;
        if (streamErr) return `erreur Google ${streamErr}`;
        return `réponse vide${lastFinish ? ' (' + lastFinish + ')' : ''}`;
      };

      /** Réponse coupée en plein milieu : on demande la SUITE (formulation neutre) et on la colle à la suite du texte déjà affiché */
      const finishCutAnswer = async (firstModel, partial, reason = 'SAFETY', fullTextSoFar) => {
        let sofar = fullTextSoFar ?? partial;
        const lengthCut = reason === 'MAX_TOKENS' || reason === 'INTERRUPTED';
        const models = [firstModel, ...candidates.filter((m) => m !== firstModel)].slice(0, 3);
        const maxAttempts = lengthCut ? 5 : 3;
        let rounds = 0;
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
          if (++rounds > 8) break;
          // Limite Vercel (~300 s de flux) : on s'arrête à temps et on propose « Continuer »
          if (Date.now() - startedAt > 230000) break;
          const base = lengthCut || attempt === 0 ? contents : pristineContents;
          const conv = [
            ...base,
            { role: 'model', parts: [{ text: sofar.slice(-12000) }] },
            {
              role: 'user',
              parts: [
                {
                  text: lengthCut
                    ? "Ta réponse précédente a été coupée (limite de longueur). Continue EXACTEMENT là où elle s'arrête — au milieu d'un mot, d'une phrase ou d'un bloc de code si besoin — sans rien répéter, sans introduction ni excuse. Si un bloc de code était ouvert, continue le code sans rouvrir de ``` et referme-le à la fin."
                    : "Ta réponse précédente a été coupée. Continue EXACTEMENT là où elle s'arrête (si le dernier mot est coupé, termine-le), sans rien répéter ni t'excuser, de manière factuelle, neutre et équilibrée, comme une agence de presse : faits datés, acteurs, enjeux, perspectives. Aucun détail opérationnel violent.",
                },
              ],
            },
          ];
          try {
            const r = await callOnce(apiKeys[Math.min(attempt, apiKeys.length - 1)], models[attempt % models.length], false, conv);
            if (!r.ok) continue;
            const out = await pipeGemini(r, models[attempt % models.length], false, true);
            if (out === 'ok') return true;
            if (out === 'suite vide') {
              logEvent('suite-vide', 'réponse déjà complète');
              return true; // le modèle n'a rien à ajouter : la réponse était terminée
            }
            if (out && out.cut) {
              sofar += out.sofar;
              attempt = out.cut === 'MAX_TOKENS' || out.cut === 'INTERRUPTED' ? Math.max(-1, attempt - 1) : attempt; // longue réponse qui avance : on continue
              if (Date.now() - startedAt > 230000) break;
              continue;
            }
          } catch (e) {}
        }
        logEvent('suite-impossible', reason);
        await send(`data: ${JSON.stringify({ boua: { incomplete: true } })}\n\n`);
        if (!lengthCut) await send(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: '\n\n> ⚠️ La suite de cette réponse a été bloquée par le filtre de sécurité de Google. Cliquez sur « ▶ Continuer » ou reformulez la question.' }] } }] })}\n\n`);
        return true;
      };

      let blockedByFilter = false;
      // VITESSE : la recherche Google intégrée de Gemini ajoute souvent 10 à 40 s.
      // Si BOUA a déjà ses propres résultats (actualités ou données temps réel), on répond directement avec eux.
      // Question d'actualité sans résultats BOUA : la recherche Google de Gemini prend le relais
      const useGoogle = (wantWeb || Boolean(body.mustSearch)) && !realtimeHit && webResults.length < 3;
      if (!isImage) logEvent('preparation', `actualites=${webResults.length} tempsreel=${realtimeHit} google=${useGoogle} ${Date.now() - startedAt} ms`);
      for (const engine of order) {
        /* ---------- Gemini : clés × modèles ---------- */
        if (engine === 'gemini') {
          let res = null;
          let model = '';
          let webUsed = false;
          let emptyTries = 0;
          outer: for (let k = 0; k < apiKeys.length; k++) {
            for (const m of candidates) {
              try {
                let r = await callOnce(apiKeys[k], m, useGoogle);
                let preMsg = '';
                if (!r.ok && useGoogle && (r.status === 400 || r.status === 429 || r.status === 504)) {
                  preMsg = await readErr(r);
                  if (!/limit:\s*0\b|no longer available|not found|not supported/i.test(preMsg)) {
                    r = await callOnce(apiKeys[k], m, false); // recherche Google indisponible : on répond sans
                    r.__web = false;
                    preMsg = '';
                  }
                }
                if (r.ok && isImage) {
                  res = r;
                  model = m;
                  break outer;
                }
                if (r.ok) {
                  const outcome = await pipeGemini(r, m, useGoogle && r.__web !== false);
                  if (outcome === 'ok') {
                    lastGood[speed] = m;
                    logEvent('ok', `${m} ${speed}${useGoogle && r.__web !== false ? ' +google' : ''} ${Date.now() - startedAt} ms`);
                    return;
                  }
                  if (outcome && outcome.cut) {
                    logEvent('reponse-coupee', `${m} ${outcome.cut} (${outcome.sofar.length} car.)`);
                    await finishCutAnswer(m, outcome.sofar, outcome.cut);
                    return;
                  }
                  if (/^réponse vide/.test(outcome) && /gemini-3|latest/.test(m) && !noThinkCfg.has(m)) {
                    noThinkCfg.add(m);
                    logEvent('vide-avec-reflexion', `${m} ${outcome} → relance sans réglage`);
                    const r2 = await callOnce(apiKeys[k], m, useGoogle);
                    if (r2.ok) {
                      const o2 = await pipeGemini(r2, m, useGoogle);
                      if (o2 === 'ok') {
                        lastGood[speed] = m;
                        return;
                      }
                      if (o2 && o2.cut) {
                        await finishCutAnswer(m, o2.sofar, o2.cut);
                        return;
                      }
                    }
                  }
                  tried.push(`Gemini ${m} → ${outcome}`);
                  logEvent('modele-echec', `${m} → ${outcome}`);
                  if (/bloquée/.test(outcome)) blockedByFilter = true;
                  if (++emptyTries >= 2) break outer; // inutile d'insister : moteur suivant / reformulation
                  continue;
                }
                lastMsg = preMsg || (await readErr(r)) || `HTTP ${r.status}`;
                const reason = reasonOf(r.status, lastMsg);
                if (reason === 'modèle indisponible') markBad(m, 6 * 3600 * 1000);
                else if (reason === 'pas de quota gratuit') markBad(m, 3600 * 1000);
                else if (reason === 'quota épuisé') markBad(m, 60 * 1000);
                else if (reason === 'trop lent') markBad(m, 10 * 60 * 1000);
                tried.push(`Gemini ${m}${apiKeys.length > 1 ? ` (clé ${k + 1})` : ''} → ${reason}`);
                logEvent('modele-echec', `${m} → ${reason}`);
                if (r.status === 400 && reason !== 'modèle indisponible') break outer; // requête refusée : on passe au moteur suivant
                if (r.status === 401 || r.status === 403) break; // clé suivante
              } catch (e) {
                lastMsg = e.message || lastMsg;
              }
            }
          }
          if (!res) continue;
          await send(`: modele ${model}\n\n`);
          await sendMeta('gemini', model, false);
          const data = await res.text();
          await send(`data: ${data.replace(/\n/g, ' ')}\n\n`);
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

      // Images : service gratuit en secours (ou directement en mode « fast »)
      if (isImage) {
        const promptText = contents[contents.length - 1]?.parts?.map((p) => p.text || '').join(' ') || '';
        const img = await freeImage(promptText, body.aspectRatio, body.seed);
        if (img) {
          await sendMeta('free', 'pollinations', false);
          await send(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ inlineData: img }] } }] })}\n\n`);
          return;
        }
        tried.push('Image gratuite → indisponible');
      }

      // Dernier recours si une réponse a été bloquée ou vide : question reformulée de façon neutre et factuelle
      if (!isImage && configured.gemini && apiKeys.length && candidates.length && tried.some((t) => /bloquée|vide/.test(t))) {
        const note = { text: "\n\n(Consigne : réponds de manière factuelle, neutre et équilibrée, comme une agence de presse ou une encyclopédie : contexte, faits récents datés, acteurs, enjeux humanitaires et perspectives. Aucune incitation, aucun détail opérationnel violent.)" };
        const variants = [
          contents.map((c, i) => (i === contents.length - 1 ? { ...c, parts: [...c.parts, note] } : c)),
          pristineContents.map((c, i) => (i === pristineContents.length - 1 ? { ...c, parts: [...c.parts, note] } : c)),
        ];
        const models = [...candidates.filter((m) => !/lite/.test(m)), ...candidates.filter((m) => /lite/.test(m))].slice(0, 2);
        for (const v of variants) {
          for (const m of models) {
            try {
              const r = await callOnce(apiKeys[0], m, false, v);
              if (!r.ok) continue;
              const outcome = await pipeGemini(r, m, false);
              if (outcome === 'ok') return;
              if (outcome && outcome.cut) {
                await finishCutAnswer(m, outcome.sofar, outcome.cut);
                return;
              }
              tried.push(`Gemini ${m} (reformulée) → ${outcome}`);
            } catch (e) {}
          }
        }
      }

      // Tous les moteurs ont échoué
      const summary = tried.join(' • ');
      logEvent('echec', summary);
      console.error('[BOUA Cloud] Échec de tous les moteurs :', summary, '—', lastMsg);
      let message = `Aucun moteur n'a pu répondre. ${summary ? 'Détail : ' + summary + '. ' : ''}Dernier message : ${lastMsg}`;
      if (blockedByFilter || tried.some((t) => /bloquée/.test(t))) {
        message = 'Le filtre de sécurité de Google a bloqué cette réponse. Reformulez la question (par exemple : « Résume les dernières actualités du Mali ») ou réessayez.';
      }
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
