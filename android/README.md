# BOUA AI — Application Android (Kotlin)

Application native qui embarque l'interface BOUA AI (dossier `app/src/main/assets/`).

## Générer l'APK avec Android Studio
1. Décompressez le ZIP, puis **File → Open** → choisissez le dossier `boua-ai-android`.
2. Attendez la fin de la synchronisation Gradle (1ère fois : quelques minutes, Internet requis).
3. Pour tester : branchez le téléphone (débogage USB) → bouton ▶ **Run**.
4. Pour l'APK : **Build → Build App Bundle(s) / APK(s) → Build APK(s)** → lien « locate » :
   `app/build/outputs/apk/debug/app-debug.apk`.
5. Pour le Play Store : **Build → Generate Signed App Bundle / APK** (créez une clé et gardez-la précieusement).

## Ce que fait l'application
- Interface complète hors-ligne (embarquée dans l'APK) ; l'IA, Tailwind et les polices utilisent Internet.
- Discussions, clés API et réglages gardés sur le téléphone (localStorage).
- Bouton 📎 : sélection d'images, PDF, CSV, code depuis le téléphone.
- Boutons ZIP / .WEBM / PNG / .MD : fichiers enregistrés dans **Téléchargements/BOUA AI**.
- Liens externes (sources web) ouverts dans le navigateur.
- Bouton retour Android, barre d'état et clavier gérés (Android 8 à 15).

## Sécurité de l'application (v2)
- Pont Android ↔ page limité à l'origine de l'app (WebMessageListener) : les aperçus de sites générés n'y ont pas accès.
- Enregistrement de fichiers limité aux types sûrs (zip, webm, png, jpg, md, json, pdf…) et à 60 Mo.
- Aucune sauvegarde cloud ni transfert d'appareil des données (discussions, clés API).
- HTTPS obligatoire (trafic non chiffré bloqué), Google Safe Browsing activé, pas de télémétrie WebView.
- Liens externes ouverts dans le navigateur, jamais dans l'app.

## Mettre à jour l'interface
- **Mode embarqué (par défaut)** : remplacez `app/src/main/assets/index.html` par la nouvelle version,
  augmentez `versionCode` dans `app/build.gradle.kts`, puis reconstruisez l'APK.
- **Mode en ligne** : dans `MainActivity.kt`, mettez votre URL Vercel dans `REMOTE_URL`
  (ex. `"https://boua-ai.vercel.app/"`). L'app chargera toujours la dernière version du site.

## Identifiant
`com.armcreat.bouaai` — modifiable dans `app/build.gradle.kts` (`applicationId`) avant la 1ère publication.

## Limites connues dans l'application
- Dictée vocale : non disponible dans la WebView Android (fonctionne dans Chrome via le site web).
- Ollama local : inutilisable depuis un téléphone (prévu pour PC).
