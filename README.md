# BOUA AI — « L'IA qui peut tout faire »

Tout le projet est réuni ici : le **site web** (à la racine) et l'**application Android** (dossier `android/`).

```
boua-ai/
├── index.html              ← l'application BOUA AI complète
├── api/chat.js             ← serveur « BOUA Cloud » : Gemini en temps réel, clé secrète côté serveur
├── manifest.json           ← installation sur téléphone / PC (PWA)
├── sw.js                   ← mode hors-ligne
├── vercel.json             ← configuration + en-têtes de sécurité Vercel
├── .vercelignore           ← Vercel ignore android/ et les fichiers Firebase
├── firestore.rules         ← règles de sécurité de la base de données (à coller dans Firebase)
├── firebase.json, .firebaserc ← configuration Firebase (projet boui-ia)
├── icon.svg, icon-192.png, icon-512.png, icon-maskable-512.png
└── android/                ← projet Android Studio (Kotlin)
    └── app/src/main/assets/index.html   ← copie du site embarquée dans l'APK
```

## 1. Site web → GitHub → Vercel (sans terminal)
1. Créez le dépôt `ARM-CREAT/boua-ai` sur GitHub.
2. **Add file → Upload files** : glissez **tout le contenu** de ce dossier (fichiers + dossier `android`).
3. vercel.com → **Add New → Project** → importez `boua-ai` → **Deploy** (Framework : Other, aucun réglage).
4. Le site est en ligne ; le dossier `android/` n'est pas publié (fichier `.vercelignore`).

## 1 bis. Activer BOUA Cloud (réponses de l'IA en temps réel) — OBLIGATOIRE
1. Créez une clé Gemini gratuite : https://aistudio.google.com/apikey → **Create API key**.
2. Vercel → votre projet → **Settings → Environment Variables** :
   - Nom : `GEMINI_API_KEY` — Valeur : votre clé — cochez Production, Preview, Development → **Save**.
3. Vercel → **Deployments** → ⋯ sur le dernier déploiement → **Redeploy**.
4. Test : connectez-vous dans BOUA AI et écrivez « Bonjour » — la réponse s'affiche mot par mot.

Sécurité : la clé Gemini reste sur le serveur (jamais dans le site). Seuls les utilisateurs connectés
peuvent utiliser BOUA Cloud (jeton Firebase vérifié), avec une limite de 20 messages par minute.
Le meilleur modèle Gemini « Flash » est choisi automatiquement (variable `GEMINI_MODEL` pour en forcer un).
Si votre adresse Vercel n'est pas `boua-ai.vercel.app`, modifiez `BOUA_CLOUD_PUBLIC_URL` dans `index.html`
(utilisée par l'application Android).

## 2. Firebase — à faire UNE fois dans console.firebase.google.com (projet boui-ia)
1. **Authentication → Sign-in method** : activez **E-mail/Mot de passe** et **Google**.
2. **Authentication → Settings → Authorized domains** : ajoutez votre domaine Vercel
   (ex. `boua-ai.vercel.app`) et votre domaine personnalisé s'il existe. Sans ça, Google refuse la connexion.
3. **Firestore Database → Créer une base de données** (mode production, région `eur3` Europe).
4. **Firestore → Règles** : remplacez tout par le contenu de `firestore.rules`, puis **Publier**.
   ⚠️ Étape indispensable : ce sont ces règles qui empêchent un utilisateur de lire les données d'un autre.
5. (Recommandé) Google Cloud Console → **API et services → Identifiants** → clé « Browser key » :
   restreignez-la aux sites `https://boua-ai.vercel.app/*` et `https://appassets.androidplatform.net/*`
   (le second est nécessaire pour l'application Android).

Ce qui est synchronisé : discussions, mémoire, agents, préférences.
Jamais synchronisé : les clés API et la base de connaissances 📚 (restent sur chaque appareil).
Dans l'application Android, la connexion se fait par e-mail (Google interdit sa connexion dans les applications de ce type).

## 3. Application Android
1. Android Studio → **File → Open** → choisissez le dossier `android`.
2. **Build → Build App Bundle(s) / APK(s) → Build APK(s)**.

## 4. Mettre à jour BOUA AI
1. Modifiez `index.html` à la racine.
2. Copiez-le aussi dans `android/app/src/main/assets/index.html` (même fichier, sinon l'app garde l'ancienne version).
3. Changez `CACHE_NAME` dans `sw.js` (ex. `boua-ai-v6`) et `versionCode` dans `android/app/build.gradle.kts`.

Astuce : pour ne plus avoir à copier `index.html`, mettez l'adresse Vercel dans `REMOTE_URL`
(`android/app/src/main/java/com/armcreat/bouaai/MainActivity.kt`) : l'app chargera toujours le site en ligne.

## Fonctions et sécurité
Voir `android/README.md` pour l'application ; côté site : streaming 5 moteurs, mémoire, base de connaissances (PDF),
11 agents experts, commandes `/`, comparaison des moteurs, coffre-fort des clés (AES-256), CSP + SRI, anti-XSS.

⚠️ Ne mettez jamais vos propres clés API dans le code : chaque utilisateur saisit les siennes dans « Multi-Moteurs IA & Clés ».
