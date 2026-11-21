package com.armcreat.bouaai

import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.ContentValues
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.util.Base64
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.FrameLayout
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import org.json.JSONObject
import java.io.File
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {

    companion object {
        /**
         * Mode HORS-LIGNE (par défaut) : l'interface est embarquée dans l'APK (dossier assets/).
         * Mode EN LIGNE : mettez l'URL Vercel ici (ex. "https://boua-ai.vercel.app/")
         * pour que l'app charge toujours la dernière version du site sans republier l'APK.
         */
        private const val REMOTE_URL = ""

        private const val ASSET_HOST = "appassets.androidplatform.net"
        private const val LOCAL_URL = "https://$ASSET_HOST/assets/index.html"

        /** Taille maximale d'un fichier enregistré depuis l'application */
        private const val MAX_SAVE_BYTES = 60L * 1024 * 1024

        /** Seuls ces types de fichiers peuvent être enregistrés dans Téléchargements */
        private val ALLOWED_EXTENSIONS = setOf(
            "zip", "webm", "png", "jpg", "jpeg", "webp", "md", "txt", "json", "csv", "html", "css", "js", "svg", "pdf"
        )
    }

    private lateinit var webView: WebView
    private var filePathCallback: ValueCallback<Array<Uri>>? = null

    private val assetLoader by lazy {
        WebViewAssetLoader.Builder()
            .setDomain(ASSET_HOST)
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()
    }

    // Sélecteur de fichiers (bouton trombone : images, PDF, CSV, code...)
    private val fileChooserLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val callback = filePathCallback ?: return@registerForActivityResult
            filePathCallback = null
            val data = result.data
            val uris: Array<Uri>? = when {
                result.resultCode != RESULT_OK || data == null -> null
                data.clipData != null -> {
                    val clip = data.clipData!!
                    Array(clip.itemCount) { i -> clip.getItemAt(i).uri }
                }
                data.data != null -> arrayOf(data.data!!)
                else -> null
            }
            callback.onReceiveValue(uris)
        }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = FrameLayout(this).apply { setBackgroundColor(Color.parseColor("#09090B")) }
        webView = WebView(this).apply { setBackgroundColor(Color.parseColor("#09090B")) }
        root.addView(webView, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        setContentView(root)

        // Marges pour la barre d'état, la barre de navigation et le clavier (Android 15 edge-to-edge)
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            WindowInsetsCompat.CONSUMED
        }

        if ((applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            WebView.setWebContentsDebuggingEnabled(true)
        }

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true            // localStorage : discussions, clés API, réglages
            databaseEnabled = true
            mediaPlaybackRequiresUserGesture = false
            allowFileAccess = false
            allowContentAccess = true
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            safeBrowsingEnabled = true          // protection Google contre les sites malveillants
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(false)
            loadWithOverviewMode = true
            useWideViewPort = true
            userAgentString = "$userAgentString BOUAAI-Android/1.0"
        }

        installSecureBridge()

        webView.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? =
                assetLoader.shouldInterceptRequest(request.url)

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val url = request.url
                val host = url.host ?: return false
                val appHost = if (REMOTE_URL.isNotBlank()) Uri.parse(REMOTE_URL).host else ASSET_HOST
                if (host == appHost) return false
                // Liens externes (sources web, documentation...) → navigateur du téléphone
                return try {
                    startActivity(Intent(Intent.ACTION_VIEW, url))
                    true
                } catch (e: ActivityNotFoundException) {
                    false
                }
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                view: WebView,
                callback: ValueCallback<Array<Uri>>,
                params: FileChooserParams
            ): Boolean {
                filePathCallback?.onReceiveValue(null)
                filePathCallback = callback
                val intent = params.createIntent().apply {
                    if (params.mode == FileChooserParams.MODE_OPEN_MULTIPLE) {
                        putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
                    }
                }
                return try {
                    fileChooserLauncher.launch(intent)
                    true
                } catch (e: ActivityNotFoundException) {
                    filePathCallback = null
                    false
                }
            }
        }

        // Bouton retour : revenir dans la page avant de quitter l'application
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (webView.canGoBack()) webView.goBack() else finish()
            }
        })

        if (savedInstanceState != null) {
            webView.restoreState(savedInstanceState)
        } else {
            webView.loadUrl(if (REMOTE_URL.isNotBlank()) REMOTE_URL else LOCAL_URL)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        webView.saveState(outState)
    }

    override fun onDestroy() {
        webView.destroy()
        super.onDestroy()
    }

    /**
     * SÉCURITÉ : pont JavaScript → Android limité à l'origine de l'application.
     * Les aperçus de sites générés (iframes isolées) et les pages externes n'y ont PAS accès.
     */
    private fun installSecureBridge() {
        val origins = mutableSetOf("https://$ASSET_HOST")
        if (REMOTE_URL.isNotBlank()) {
            val u = Uri.parse(REMOTE_URL)
            origins.add("${u.scheme}://${u.host}")
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(webView, "AndroidBridge", origins) {
                    _: WebView, message: WebMessageCompat, _: Uri, isMainFrame: Boolean, _: JavaScriptReplyProxy ->
                if (!isMainFrame) return@addWebMessageListener
                try {
                    val json = JSONObject(message.data ?: return@addWebMessageListener)
                    if (json.optString("type") == "saveFile") {
                        handleSave(json.optString("data"), json.optString("name"), json.optString("mime"))
                    }
                } catch (_: Exception) {
                }
            }
        } else {
            // WebView très ancienne : pont classique (mêmes contrôles de taille et de type)
            webView.addJavascriptInterface(LegacyBridge(), "AndroidBridge")
        }
    }

    inner class LegacyBridge {
        @JavascriptInterface
        fun saveFile(base64: String, fileName: String, mimeType: String) = handleSave(base64, fileName, mimeType)
    }

    private fun handleSave(base64: String, fileName: String, mimeType: String) {
        thread {
            val message = try {
                if (base64.length.toLong() * 3 / 4 > MAX_SAVE_BYTES) throw IllegalArgumentException("fichier trop volumineux")
                val safeName = fileName
                    .replace(Regex("[\\\\/:*?\"<>|\\p{Cntrl}]"), "_")
                    .replace("..", "_")
                    .take(120)
                    .ifBlank { "boua-ai-fichier.txt" }
                val ext = safeName.substringAfterLast('.', "").lowercase()
                if (ext !in ALLOWED_EXTENSIONS) throw IllegalArgumentException("type de fichier non autorisé (.$ext)")
                val bytes = Base64.decode(base64, Base64.DEFAULT)
                saveToDownloads(bytes, safeName, mimeType.ifBlank { "application/octet-stream" }.take(100))
            } catch (e: Exception) {
                "Échec de l'enregistrement : ${e.message}"
            }
            runOnUiThread { Toast.makeText(this@MainActivity, message, Toast.LENGTH_LONG).show() }
        }
    }

    private fun saveToDownloads(bytes: ByteArray, name: String, mime: String): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, mime)
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/BOUA AI")
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = contentResolver
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IllegalStateException("Stockage indisponible")
            resolver.openOutputStream(uri)?.use { it.write(bytes) }
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
            return "Enregistré : Téléchargements/BOUA AI/$name"
        } else {
            val dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: filesDir
            val file = File(dir, name)
            file.writeBytes(bytes)
            return "Enregistré : ${file.absolutePath}"
        }
    }
}
