package dev.globalghost.net

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.*

class MainActivity : Activity() {

    private val VPN_REQUEST_CODE = 1001
    private val QR_SCAN_REQUEST_CODE = 1002
    private var pendingInvite: String? = null
    private var pendingInstallApkFile: java.io.File? = null

    private var currentModeIndex = 1 // 0 = Fast, 1 = Stealth, 2 = Multi-Hop
    private val modes = arrayOf("Fast", "Stealth", "Multi-Hop")

    private lateinit var editRemoteAddr: EditText
    private lateinit var editDnsServer: EditText
    private lateinit var centerButtonFrame: FrameLayout
    private lateinit var centerLedView: View
    private lateinit var txtCenterState: TextView
    private lateinit var txtLocationValue: TextView
    private lateinit var txtLocationSub: TextView
    private lateinit var txtModeValue: TextView
    private lateinit var txtModeSub: TextView
    private lateinit var btnUpdateBadge: Button
    private lateinit var txtUpdateStatus: TextView
    private lateinit var btnUpdateAction: TextView
    private lateinit var txtPeersHeader: TextView
    private lateinit var peerListContainer: LinearLayout

    private val handler = Handler(Looper.getMainLooper())

    private val statusUpdater = object : Runnable {
        override fun run() {
            updateStatus()
            handler.postDelayed(this, 1200)
        }
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
        actionBar?.hide()
        window.statusBarColor = Color.parseColor("#232428")
        window.navigationBarColor = Color.parseColor("#0C0D0F")

        val currentVerName = getAppVersionName()

        val scroll = ScrollView(this).apply {
            background = GradientDrawable(
                GradientDrawable.Orientation.TOP_BOTTOM,
                intArrayOf(
                    Color.parseColor("#232428"),
                    Color.parseColor("#141518"),
                    Color.parseColor("#0C0D0F")
                )
            )
            isFillViewport = true
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(28), dp(24), dp(28))
        }
        scroll.addView(root)

        // ── Top Bar (Monolith Coal) ──
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(24))
        }

        val title = TextView(this).apply {
            text = "Vantablack"
            textSize = 17f
            setTypeface(Typeface.DEFAULT, Typeface.BOLD)
            setTextColor(Color.parseColor("#F4F1EA"))
        }
        header.addView(title)

        val ver = TextView(this).apply {
            text = "v$currentVerName"
            textSize = 12f
            setTextColor(Color.parseColor("#8E8D8A"))
            layoutParams = LinearLayout.LayoutParams(
                0,
                LinearLayout.LayoutParams.WRAP_CONTENT,
                1f
            ).apply { setMargins(dp(10), 0, 0, 0) }
            setOnClickListener { checkUpdate(userInitiated = true) }
        }
        header.addView(ver)

        btnUpdateBadge = Button(this).apply {
            text = "⚡ Update"
            textSize = 11f
            isAllCaps = false
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#0C0D0F"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#F4F1EA"))
                cornerRadius = dp(999).toFloat()
            }
            setPadding(dp(14), dp(6), dp(14), dp(6))
            visibility = View.GONE
            setOnClickListener { triggerImmediateUpdate() }
        }
        header.addView(btnUpdateBadge)
        root.addView(header)

        // ── Center Stage: Machined Brushed-Steel Button + Location / Mode Flanks ──
        val heroSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, dp(16), 0, dp(24))
        }

        centerButtonFrame = FrameLayout(this).apply {
            val size = dp(176)
            layoutParams = LinearLayout.LayoutParams(size, size).apply {
                gravity = Gravity.CENTER_HORIZONTAL
            }
            val steelRing = GradientDrawable(
                GradientDrawable.Orientation.TOP_BOTTOM,
                intArrayOf(
                    Color.parseColor("#46474C"),
                    Color.parseColor("#707278"),
                    Color.parseColor("#B9BAC0")
                )
            ).apply {
                shape = GradientDrawable.OVAL
                setStroke(dp(1), Color.parseColor("#99FFFFFF"))
            }
            val innerCore = GradientDrawable(
                GradientDrawable.Orientation.TOP_BOTTOM,
                intArrayOf(
                    Color.parseColor("#2B2D32"),
                    Color.parseColor("#191A1D"),
                    Color.parseColor("#121316")
                )
            ).apply {
                shape = GradientDrawable.OVAL
                setStroke(dp(1), Color.parseColor("#24FFFFFF"))
            }
            val layers = LayerDrawable(arrayOf(steelRing, innerCore)).apply {
                val inset = dp(13)
                setLayerInset(1, inset, inset, inset, inset)
            }
            background = layers
            elevation = dp(16).toFloat()
            isClickable = true
            isFocusable = true
            setOnClickListener {
                if (GhostVpnService.isVpnActive(this@MainActivity)) {
                    stopVpn()
                } else {
                    startVpn()
                }
            }

            val innerCol = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                layoutParams = FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT
                )
            }

            centerLedView = View(context).apply {
                val d = dp(11)
                layoutParams = LinearLayout.LayoutParams(d, d).apply {
                    setMargins(0, 0, 0, dp(10))
                }
                background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(Color.parseColor("#33FFFFFF"))
                }
            }
            innerCol.addView(centerLedView)

            txtCenterState = TextView(context).apply {
                text = "OFF"
                textSize = 12f
                letterSpacing = 0.16f
                gravity = Gravity.CENTER
                textAlignment = View.TEXT_ALIGNMENT_CENTER
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    gravity = Gravity.CENTER_HORIZONTAL
                }
            }
            innerCol.addView(txtCenterState)

            addView(innerCol)
        }
        heroSection.addView(centerButtonFrame)

        // Flanks Row (Location & Mode)
        val flanksRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            weightSum = 2f
            setPadding(dp(8), dp(24), dp(8), 0)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val leftFlank = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.START
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            addView(TextView(context).apply {
                text = "LOCATION"
                textSize = 10f
                letterSpacing = 0.14f
                setTextColor(Color.parseColor("#787774"))
            })
            txtLocationValue = TextView(context).apply {
                text = "Zurich"
                textSize = 19f
                setTypeface(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, dp(2), 0, 0)
            }
            addView(txtLocationValue)
            txtLocationSub = TextView(context).apply {
                text = "Switzerland"
                textSize = 12f
                setTextColor(Color.parseColor("#9E9C98"))
            }
            addView(txtLocationSub)
        }

        val rightFlank = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.END
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                currentModeIndex = (currentModeIndex + 1) % modes.size
                txtModeValue.text = modes[currentModeIndex]
            }
            addView(TextView(context).apply {
                text = "MODE"
                textSize = 10f
                letterSpacing = 0.14f
                gravity = Gravity.END
                setTextColor(Color.parseColor("#787774"))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            })
            txtModeValue = TextView(context).apply {
                text = modes[currentModeIndex]
                textSize = 19f
                gravity = Gravity.END
                setTypeface(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, dp(2), 0, 0)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            addView(txtModeValue)
            txtModeSub = TextView(context).apply {
                text = "Direct"
                textSize = 12f
                gravity = Gravity.END
                setTextColor(Color.parseColor("#9E9C98"))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            addView(txtModeSub)
        }

        flanksRow.addView(leftFlank)
        flanksRow.addView(rightFlank)
        heroSection.addView(flanksRow)
        root.addView(heroSection)

        // ── Quick Pairing Pill Dock (+ Pair Phone QR & Paste Invite) ──
        val dockRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            weightSum = 2f
            setPadding(dp(6), dp(6), dp(6), dp(6))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0DFFFFFF"))
                setStroke(1, Color.parseColor("#1AFFFFFF"))
                cornerRadius = dp(999).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, dp(16)) }
        }

        val btnScanQr = Button(this).apply {
            text = "+ Scan QR Code"
            textSize = 12f
            isAllCaps = false
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#0C0D0F"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#F4F1EA"))
                cornerRadius = dp(999).toFloat()
            }
            setPadding(0, dp(10), 0, dp(10))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(0, 0, dp(4), 0)
            }
            setOnClickListener { launchQrScanner() }
        }

        val btnPasteInvite = Button(this).apply {
            text = "Paste Invite Link"
            textSize = 12f
            isAllCaps = false
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#F4F1EA"))
            background = GradientDrawable().apply {
                setColor(Color.TRANSPARENT)
                cornerRadius = dp(999).toFloat()
            }
            setPadding(0, dp(10), 0, dp(10))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(dp(4), 0, 0, 0)
            }
            setOnClickListener { pasteOrPromptInvite() }
        }

        dockRow.addView(btnScanQr)
        dockRow.addView(btnPasteInvite)
        root.addView(dockRow)

        // ── Linked Devices Sheet ──
        val cardPeers = createCoalCard().apply {
            val topRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 0, 0, dp(10))
            }
            txtPeersHeader = TextView(context).apply {
                text = "Linked Devices"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            topRow.addView(txtPeersHeader)

            val btnFindWifi = TextView(context).apply {
                text = "Find on Wi-Fi"
                textSize = 11f
                setTextColor(Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(12), dp(5), dp(12), dp(5))
                setOnClickListener {
                    if (GhostVpnService.isRunning) {
                        GhostVpnService.triggerScan { count ->
                            handler.post {
                                updateStatus()
                                Toast.makeText(this@MainActivity, "Found $count device(s)", Toast.LENGTH_SHORT).show()
                            }
                        }
                    } else {
                        Toast.makeText(this@MainActivity, "Tap the center button to connect first", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            topRow.addView(btnFindWifi)
            addView(topRow)

            peerListContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }
            addView(peerListContainer)
        }
        root.addView(cardPeers)

        // ── Hidden / Optional Endpoint & DNS state (preserved for invite import) ──
        val prefs = getSharedPreferences("ggn_vpn", MODE_PRIVATE)
        val savedHub = prefs.getString("hub_addr", null)
        val savedDns = prefs.getString("dns_server", null)
        editRemoteAddr = EditText(this).apply {
            setText(savedHub ?: "")
            visibility = View.GONE
        }
        editDnsServer = EditText(this).apply {
            setText(savedDns ?: "")
            visibility = View.GONE
        }
        root.addView(editRemoteAddr)
        root.addView(editDnsServer)

        // ── App Updates Row (One-Tap Update) ──
        val cardUpdate = createCoalCard().apply {
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val textCol = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "App Updates"
                    textSize = 13f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                txtUpdateStatus = TextView(context).apply {
                    text = "Vantablack v$currentVerName is installed"
                    textSize = 11f
                    setTextColor(Color.parseColor("#9E9C98"))
                    setPadding(0, dp(2), 0, 0)
                }
                addView(txtUpdateStatus)
            }
            row.addView(textCol)

            btnUpdateAction = TextView(context).apply {
                text = "Check"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(14), dp(7), dp(14), dp(7))
            }
            row.addView(btnUpdateAction)
            setOnClickListener { triggerImmediateUpdate() }
            addView(row)
        }
        root.addView(cardUpdate)

        setContentView(scroll)
        updateStatus()

        // Automatic update check shortly after launch
        handler.postDelayed({ checkUpdate(userInitiated = false) }, 1500)

        if (intent?.getBooleanExtra("auto_connect", false) == true && !GhostVpnService.isVpnActive(this)) {
            handler.postDelayed({ startVpn() }, 300)
        }
        intent?.dataString?.trim()?.takeIf {
            it.startsWith("vb://") || it.startsWith("vb-net://") || it.startsWith("vb-fleet://")
        }?.let { handleInviteString(it) }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent?.getBooleanExtra("auto_connect", false) == true && !GhostVpnService.isVpnActive(this)) {
            handler.postDelayed({ startVpn() }, 300)
        }
        intent?.dataString?.trim()?.takeIf {
            it.startsWith("vb://") || it.startsWith("vb-net://") || it.startsWith("vb-fleet://")
        }?.let { handleInviteString(it) }
    }

    override fun onResume() {
        super.onResume()
        handler.post(statusUpdater)
        // If user just returned from granting "Install unknown apps" permission, resume APK install automatically
        val pendingApk = pendingInstallApkFile
        if (pendingApk != null && pendingApk.exists()) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O || packageManager.canRequestPackageInstalls()) {
                pendingInstallApkFile = null
                installApk(pendingApk)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(statusUpdater)
    }

    private fun getAppVersionName(): String {
        return try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "2.0.1"
        } catch (_: Throwable) {
            "2.0.1"
        }
    }

    private fun createCoalCard(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0DFFFFFF"))
                setStroke(1, Color.parseColor("#18FFFFFF"))
                cornerRadius = dp(16).toFloat()
            }
            setPadding(dp(18), dp(16), dp(18), dp(16))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, dp(12)) }
        }
    }

    private fun updateStatus() {
        val isConnected = GhostVpnService.isVpnActive(this)
        if (isConnected) {
            val peers = GhostVpnService.getPeersCount()
            txtPeersHeader.text = "Linked Devices ($peers)"

            val activeExit = GhostVpnService.getActiveExitNode()
            if (activeExit.isNotEmpty() && activeExit != "auto") {
                txtLocationValue.text = activeExit
                txtLocationSub.text = "Home Exit"
            } else {
                txtLocationValue.text = "Zurich"
                txtLocationSub.text = "Switzerland"
            }

            peerListContainer.removeAllViews()
            val discovered = GhostVpnService.getDiscoveredPeers()
            if (discovered.isEmpty() && peers > 0) {
                peerListContainer.addView(createPeerRow(activeExit.ifEmpty { "Linked Mesh Exit" }, true))
            } else if (discovered.isEmpty()) {
                peerListContainer.addView(TextView(this).apply {
                    text = "Protected — waiting for linked devices..."
                    textSize = 12f
                    setTextColor(Color.parseColor("#8E8D8A"))
                    setPadding(0, dp(4), 0, dp(4))
                })
            } else {
                for (peer in discovered) {
                    peerListContainer.addView(createPeerRow(peer, peer == activeExit))
                }
            }
            updateUiState(true)
        } else {
            txtPeersHeader.text = "Linked Devices (0)"
            val configured = editRemoteAddr.text.toString().trim()
            if (configured.isNotEmpty() && configured != "auto") {
                txtLocationValue.text = configured
                txtLocationSub.text = "Paired Exit"
            } else {
                txtLocationValue.text = "Zurich"
                txtLocationSub.text = "Switzerland"
            }
            peerListContainer.removeAllViews()
            peerListContainer.addView(TextView(this).apply {
                text = "Scan a QR code from your computer or tap the center button"
                textSize = 12f
                setTextColor(Color.parseColor("#8E8D8A"))
                setPadding(0, dp(4), 0, dp(4))
            })
            updateUiState(false)
        }
    }

    private fun createPeerRow(addr: String, isExit: Boolean): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0AFFFFFF"))
                setStroke(1, Color.parseColor("#14FFFFFF"))
                cornerRadius = dp(12).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, dp(4), 0, dp(4)) }

            setOnClickListener {
                if (GhostVpnService.isRunning && !isExit && addr.isNotEmpty() && !addr.startsWith("Auto")) {
                    GhostVpnService.selectExitNode(addr) { ok ->
                        handler.post {
                            if (ok) {
                                Toast.makeText(this@MainActivity, "Routing through $addr", Toast.LENGTH_SHORT).show()
                                updateStatus()
                            }
                        }
                    }
                }
            }

            addView(View(context).apply {
                val d = dp(8)
                layoutParams = LinearLayout.LayoutParams(d, d).apply {
                    setMargins(0, 0, dp(10), 0)
                }
                background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(Color.parseColor("#F4F1EA"))
                }
            })

            addView(TextView(context).apply {
                text = addr
                textSize = 12f
                setTextColor(Color.parseColor("#F4F1EA"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })

            addView(TextView(context).apply {
                text = if (isExit) "Home Exit" else "Use as Exit"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(if (isExit) Color.parseColor("#0C0D0F") else Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(if (isExit) Color.parseColor("#F4F1EA") else Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(10), dp(4), dp(10), dp(4))
            })
        }
    }

    private fun updateUiState(connected: Boolean) {
        if (connected) {
            txtCenterState.text = "PROTECTED"
            txtModeSub.text = "Encrypted"
            centerLedView.background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(Color.parseColor("#F4F1EA"))
            }
            centerLedView.elevation = dp(6).toFloat()
        } else {
            txtCenterState.text = "OFF"
            txtModeSub.text = "Direct"
            centerLedView.background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(Color.parseColor("#33FFFFFF"))
            }
            centerLedView.elevation = 0f
        }
    }

    private fun stopVpn() {
        val stopIntent = Intent(this, GhostVpnService::class.java).apply {
            action = GhostVpnService.ACTION_STOP
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(stopIntent)
        } else {
            startService(stopIntent)
        }
        stopService(Intent(this, GhostVpnService::class.java))
        GhostVpnService.isRunning = false
        GhostVpnService.activePtr = 0L
        updateUiState(false)
        updateStatus()
        Toast.makeText(this, "Protection Off", Toast.LENGTH_SHORT).show()
    }

    private fun startVpn() {
        val targetAddr = editRemoteAddr.text.toString().trim().ifEmpty { "auto" }
        val customDns = editDnsServer.text.toString().trim().ifEmpty { "auto" }
        getSharedPreferences("ggn_vpn", MODE_PRIVATE).edit()
            .putString("hub_addr", if (targetAddr == "auto") "" else targetAddr)
            .putString("dns_server", if (customDns == "auto") "" else customDns)
            .apply()

        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
        } else {
            onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == QR_SCAN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                val contents = data?.getStringExtra("SCAN_RESULT") ?: data?.dataString
                if (!contents.isNullOrBlank()) {
                    handleInviteString(contents)
                }
            }
            return
        }
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            val targetAddr = editRemoteAddr.text.toString().trim().ifEmpty { "auto" }
            val customDns = editDnsServer.text.toString().trim().ifEmpty { "auto" }
            val serviceIntent = Intent(this, GhostVpnService::class.java).apply {
                action = GhostVpnService.ACTION_START
                putExtra(GhostVpnService.EXTRA_HUB_FP, "auto")
                putExtra(GhostVpnService.EXTRA_HUB_ADDR, targetAddr)
                putExtra(GhostVpnService.EXTRA_DNS, customDns)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
            GhostVpnService.isRunning = true
            updateUiState(true)
            updateStatus()
        } else if (requestCode == VPN_REQUEST_CODE) {
            Toast.makeText(this, "VPN permission declined", Toast.LENGTH_SHORT).show()
        }
    }

    // ── QR Scanner & Invite Handling ──
    private fun launchQrScanner() {
        try {
            com.google.zxing.integration.android.IntentIntegrator(this)
                .setDesiredBarcodeFormats(com.google.zxing.integration.android.IntentIntegrator.QR_CODE)
                .setPrompt("Scan Vantablack QR Code")
                .setBeepEnabled(false)
                .setOrientationLocked(false)
                .setRequestCode(QR_SCAN_REQUEST_CODE)
                .initiateScan()
        } catch (_: Throwable) {
            try {
                val intent = Intent("com.google.zxing.client.android.SCAN").apply {
                    putExtra("SCAN_MODE", "QR_CODE_MODE")
                }
                startActivityForResult(intent, QR_SCAN_REQUEST_CODE)
            } catch (_: Throwable) {
                Toast.makeText(this, "Camera scanner unavailable — paste invite link", Toast.LENGTH_SHORT).show()
                promptPasteInvite()
            }
        }
    }

    private fun pasteOrPromptInvite() {
        val clip = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clipText = clip.primaryClip?.getItemAt(0)?.text?.toString()?.trim() ?: ""
        if (clipText.startsWith("vb-net://") || clipText.startsWith("vb://") || clipText.startsWith("vb-fleet://")) {
            handleInviteString(clipText)
        } else {
            promptPasteInvite(clipText)
        }
    }

    private fun promptPasteInvite(prefill: String = "") {
        val input = EditText(this).apply {
            hint = "vb-net://... or vb://2...."
            setText(prefill)
            setSingleLine(false)
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Link Device")
            .setMessage("Paste a Vantablack invite link from another device:")
            .setView(input)
            .setPositiveButton("Link") { _, _ ->
                val text = input.text.toString().trim()
                if (text.isNotEmpty()) {
                    handleInviteString(text)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun handleInviteString(raw: String) {
        val invite = raw.trim()
        if (!invite.startsWith("vb-net://") && !invite.startsWith("vb://") && !invite.startsWith("vb-fleet://")) {
            Toast.makeText(this, "Invalid invite link", Toast.LENGTH_SHORT).show()
            return
        }
        pendingInvite = invite
        val p = GhostVpnService.activePtr
        if (p != 0L) {
            val res = try { GhostCore.importInvite(p, invite) } catch (e: Throwable) { "err:${e.message}" }
            if (res.startsWith("ok:")) {
                val endpoint = res.removePrefix("ok:")
                if (endpoint.isNotEmpty()) {
                    editRemoteAddr.setText(endpoint)
                }
                Toast.makeText(this, "Device linked ($endpoint)", Toast.LENGTH_SHORT).show()
                updateStatus()
            } else {
                Toast.makeText(this, "Invite error: ${res.removePrefix("err:")}", Toast.LENGTH_LONG).show()
            }
        } else {
            Toast.makeText(this, "Invite ready — tap the center button to connect", Toast.LENGTH_SHORT).show()
        }
    }

    // ── In-App Software Updater (Redirect-Safe & Instant Install) ──
    private var availableUpdateUrl: String? = null
    private var availableUpdateVer: String? = null

    private fun isNewerVersion(latest: String, current: String): Boolean {
        val cleanLatest = latest.trimStart('v')
        val cleanCurrent = current.trimStart('v')
        val lParts = cleanLatest.split('.', '-').mapNotNull { it.toIntOrNull() }
        val cParts = cleanCurrent.split('.', '-').mapNotNull { it.toIntOrNull() }
        val len = maxOf(lParts.size, cParts.size)
        for (i in 0 until len) {
            val l = lParts.getOrElse(i) { 0 }
            val c = cParts.getOrElse(i) { 0 }
            if (l > c) return true
            if (l < c) return false
        }
        return false
    }

    private fun triggerImmediateUpdate() {
        val url = availableUpdateUrl
        val ver = availableUpdateVer
        if (!url.isNullOrEmpty() && !ver.isNullOrEmpty()) {
            downloadAndInstallApk(url, "vantablack-${ver.trimStart('v')}-android.apk")
        } else {
            checkUpdate(userInitiated = true)
        }
    }

    private fun checkUpdate(userInitiated: Boolean) {
        if (userInitiated) {
            txtUpdateStatus.text = "Checking GitHub releases..."
            btnUpdateAction.text = "Checking..."
        }
        Thread {
            try {
                val conn = openFollowingRedirects("https://api.github.com/repos/KELLERBABG/Vantablack/releases/latest")
                val code = conn.responseCode
                if (code in 200..299) {
                    val body = conn.inputStream.bufferedReader().readText()
                    val json = org.json.JSONObject(body)
                    val tag = json.optString("tag_name", "")
                    val assets = json.optJSONArray("assets")
                    var apkUrl: String? = null
                    if (assets != null) {
                        for (i in 0 until assets.length()) {
                            val asset = assets.getJSONObject(i)
                            val name = asset.optString("name", "")
                            if (name.endsWith(".apk")) {
                                val candidate = asset.optString("browser_download_url", "")
                                if (candidate.isNotEmpty()) {
                                    apkUrl = candidate
                                    if (name.startsWith("vantablack-")) break
                                }
                            }
                        }
                    }

                    val currentVer = getAppVersionName()
                    val hasUpdate = tag.isNotEmpty() && !apkUrl.isNullOrEmpty() && isNewerVersion(tag, currentVer)
                    handler.post {
                        if (hasUpdate && apkUrl != null) {
                            availableUpdateUrl = apkUrl
                            availableUpdateVer = tag
                            btnUpdateBadge.visibility = View.VISIBLE
                            btnUpdateBadge.text = "⚡ Update $tag"
                            txtUpdateStatus.text = "Vantablack $tag is ready to install"
                            btnUpdateAction.text = "Install $tag"
                            btnUpdateAction.setTextColor(Color.parseColor("#0C0D0F"))
                            btnUpdateAction.background = GradientDrawable().apply {
                                setColor(Color.parseColor("#F4F1EA"))
                                cornerRadius = dp(999).toFloat()
                            }
                            if (userInitiated) {
                                downloadAndInstallApk(apkUrl, "vantablack-${tag.trimStart('v')}-android.apk")
                            }
                        } else {
                            btnUpdateBadge.visibility = View.GONE
                            txtUpdateStatus.text = "Vantablack v$currentVer is up to date"
                            btnUpdateAction.text = "Check"
                            if (userInitiated) {
                                Toast.makeText(this, "Vantablack v$currentVer is up to date", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                } else if (userInitiated) {
                    handler.post {
                        txtUpdateStatus.text = "Update check failed (HTTP $code)"
                        btnUpdateAction.text = "Retry"
                        Toast.makeText(this, "Update check failed (HTTP $code)", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Throwable) {
                if (userInitiated) {
                    handler.post {
                        txtUpdateStatus.text = "Could not reach GitHub"
                        btnUpdateAction.text = "Retry"
                        Toast.makeText(this, "Update check error: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }.start()
    }

    private fun openFollowingRedirects(startUrl: String, maxHops: Int = 5): java.net.HttpURLConnection {
        var currentUrl = startUrl
        var hops = 0
        while (hops < maxHops) {
            val conn = java.net.URL(currentUrl).openConnection() as java.net.HttpURLConnection
            conn.connectTimeout = 10000
            conn.readTimeout = 20000
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "Vantablack-Android/${getAppVersionName()}")
            conn.connect()
            val code = conn.responseCode
            if (code in intArrayOf(301, 302, 303, 307, 308)) {
                val loc = conn.getHeaderField("Location")
                conn.disconnect()
                if (loc.isNullOrEmpty()) break
                currentUrl = java.net.URL(java.net.URL(currentUrl), loc).toString()
                hops++
            } else {
                return conn
            }
        }
        return (java.net.URL(currentUrl).openConnection() as java.net.HttpURLConnection).apply {
            connectTimeout = 10000
            readTimeout = 20000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "Vantablack-Android/${getAppVersionName()}")
            connect()
        }
    }

    private fun downloadAndInstallApk(downloadUrl: String, fileName: String) {
        val progressDialog = android.app.ProgressDialog(this).apply {
            setTitle("Updating Vantablack")
            setMessage("Downloading latest Android release...")
            setProgressStyle(android.app.ProgressDialog.STYLE_HORIZONTAL)
            isIndeterminate = false
            max = 100
            setCancelable(false)
            show()
        }

        Thread {
            try {
                val targetDir = getExternalFilesDir(android.os.Environment.DIRECTORY_DOWNLOADS) ?: cacheDir
                val targetFile = java.io.File(targetDir, fileName)
                if (targetFile.exists()) targetFile.delete()

                val conn = openFollowingRedirects(downloadUrl)
                val code = conn.responseCode
                if (code !in 200..299) {
                    throw IllegalStateException("HTTP $code")
                }

                val fileLength = conn.contentLength
                val input = java.io.BufferedInputStream(conn.inputStream)
                val output = java.io.FileOutputStream(targetFile)

                val buffer = ByteArray(8192)
                var total: Long = 0
                var count: Int
                while (input.read(buffer).also { count = it } != -1) {
                    total += count
                    if (fileLength > 0) {
                        val progress = ((total * 100) / fileLength).toInt()
                        handler.post { progressDialog.progress = progress }
                    }
                    output.write(buffer, 0, count)
                }
                output.flush()
                output.close()
                input.close()

                if (targetFile.length() < 50_000L) {
                    throw IllegalStateException("Downloaded APK is incomplete (${targetFile.length()} bytes)")
                }

                handler.post {
                    progressDialog.dismiss()
                    installApk(targetFile)
                }
            } catch (e: Throwable) {
                handler.post {
                    progressDialog.dismiss()
                    Toast.makeText(this, "Direct download fallback: ${e.message}", Toast.LENGTH_LONG).show()
                    try {
                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(downloadUrl)))
                    } catch (_: Throwable) {}
                }
            }
        }.start()
    }

    private fun installApk(file: java.io.File) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (!packageManager.canRequestPackageInstalls()) {
                    pendingInstallApkFile = file
                    Toast.makeText(
                        this,
                        "Enable 'Allow from this source' — update will install automatically when you return",
                        Toast.LENGTH_LONG
                    ).show()
                    val permissionIntent = Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(permissionIntent)
                    return
                }
            }

            val uri = androidx.core.content.FileProvider.getUriForFile(
                this,
                "${packageName}.provider",
                file
            )
            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(installIntent)
        } catch (e: Throwable) {
            Toast.makeText(this, "Opening browser download for update...", Toast.LENGTH_LONG).show()
            availableUpdateUrl?.let { url ->
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                } catch (_: Throwable) {}
            }
        }
    }
}
