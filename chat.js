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
  if (payload.firebase?.sign_in_provider === 'anonymous') throw new Error('Connexion avec un compte requise');

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
function rateLimited(uid) {
  const now = Date.now();
  const arr = (hits.get(uid) || []).filter((t) => now - t < 60000);
  if (arr.length >= RATE_LIMIT_PER_MIN) {
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
  const flash = gen.filter((n) => /^gemini-[\d.]+-flash/.test(n) && notSpecial(n));
  const byVersion = (a, b) => versionOf(b) - versionOf(a);
  const stable = flash.filter((n) => !/preview/.test(n));
  const text = [
    ...stable.filter((n) => !/lite/.test(n)).sort(byVersion),
    ...stable.filter((n) => /lite/.test(n)).sort(byVersion),
    ...gen.filter((n) => /^gemini-flash(-lite)?-latest$/.test(n)),
    ...flash.filter((n) => /preview/.test(n)).sort(byVersion),
  ];
  const images = gen.filter((n) => /^gemini-[\d.]+-flash.*image/.test(n) && !/tts|audio|live/.test(n));
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
    return new Response(JSON.stringify({ service: 'BOUA Cloud', version: 3, clesConfigurees: keys.length, modelesTexte: m.text.slice(0, 6), modelesImage: m.image.slice(0, 3) }, null, 2), {
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
  if (!apiKey) return jsonError(503, 'BOUA Cloud non configuré : ajoutez GEMINI_API_KEY dans Vercel (Settings → Environment Variables), puis redéployez.', origin);

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
  if (rateLimited(user.sub)) return jsonError(429, 'Trop de messages en une minute. Patientez quelques secondes.', origin);

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
  const callOnce = (key, model, withWeb) => {
    const payload = { contents };
    if (system && !isImage) payload.systemInstruction = { parts: [{ text: system }] };
    payload.generationConfig = isImage
      ? { responseModalities: ['TEXT', 'IMAGE'], ...(body.aspectRatio ? { imageConfig: { aspectRatio: String(body.aspectRatio).slice(0, 8) } } : {}) }
      : { temperature };
    if (withWeb) payload.tools = [{ google_search: {} }];
    const url = isImage ? `${GEMINI_BASE}/models/${encodeURIComponent(model)}:generateContent` : `${GEMINI_BASE}/models/${encodeURIComponent(model)}:streamGenerateContent?alt=sse`;
    // SÉCURITÉ : la clé part dans un en-tête, jamais dans l'URL
    return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key }, body: JSON.stringify(payload) });
  };
  const readErr = async (r) => {
    try {
      const j = await r.json();
      return String(j?.error?.message || '').slice(0, 400);
    } catch (e) {
      return '';
    }
  };

  const models = await resolveModels(apiKey);
  const candidates = (isImage ? models.image : models.text).slice(0, 6);
  if (!candidates.length) return jsonError(503, 'Aucun modèle Gemini disponible pour cette clé.', origin);

  let res = null;
  let model = '';
  const tried = [];
  let lastStatus = 502;
  let lastMsg = 'Impossible de joindre Gemini.';
  outer: for (let k = 0; k < apiKeys.length; k++) {
    for (const m of candidates) {
      try {
        let r = await callOnce(apiKeys[k], m, wantWeb);
        if (!r.ok && wantWeb && (r.status === 400 || r.status === 429)) {
          await readErr(r);
          r = await callOnce(apiKeys[k], m, false); // recherche Google indisponible : on répond sans
        }
        if (r.ok) {
          res = r;
          model = m;
          break outer;
        }
        lastStatus = r.status;
        lastMsg = (await readErr(r)) || `HTTP ${r.status}`;
        tried.push(`clé ${k + 1} · ${m} → ${r.status}`);
        if (r.status === 400) break outer; // la requête elle-même est refusée : inutile d'insister
        if (r.status === 401 || r.status === 403) break; // clé invalide : clé suivante
        // 404 (modèle retiré) ou 429 (quota de ce modèle) ou 5xx : modèle suivant
      } catch (e) {
        lastMsg = e.message || lastMsg;
      }
    }
  }
  if (!res) {
    console.error('[BOUA Cloud] Échec Gemini :', tried.join(' | '), '—', lastMsg);
    if (lastStatus === 429) {
      return jsonError(
        429,
        `Quota Gemini gratuit atteint sur toutes les clés et tous les modèles essayés (${tried.length} essais). Réessayez dans une minute. Détail Google : ${lastMsg}`,
        origin
      );
    }
    if (lastStatus === 401 || lastStatus === 403) return jsonError(502, `Clé Gemini refusée par Google (vérifiez GEMINI_API_KEY dans Vercel). Détail : ${lastMsg}`, origin);
    return jsonError(502, `Erreur Gemini : ${lastMsg}`, origin);
  }

  const headers = {
    ...corsHeaders(origin),
    'Cache-Control': 'no-store',
    'X-BOUA-Model': model,
    'X-Content-Type-Options': 'nosniff',
  };
  if (isImage) return new Response(res.body, { status: 200, headers: { ...headers, 'Content-Type': 'application/json' } });
  // Flux en temps réel transmis tel quel au navigateur
  return new Response(res.body, { status: 200, headers: { ...headers, 'Content-Type': 'text/event-stream; charset=utf-8' } });
}
