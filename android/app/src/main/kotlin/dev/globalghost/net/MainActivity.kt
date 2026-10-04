package dev.globalghost.net

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.widget.*
import java.util.Locale

class MainActivity : Activity() {

    private val VPN_REQUEST_CODE = 1001
    private lateinit var editRemoteAddr: EditText
    private lateinit var btnConnect: Button
    private lateinit var btnScanLan: Button
    private lateinit var btnLeakTest: Button
    private lateinit var btnCopyFp: Button
    private lateinit var txtStatus: TextView
    private lateinit var txtMode: TextView
    private lateinit var txtFingerprint: TextView

    // Telemetry
    private lateinit var txtDownSpeed: TextView
    private lateinit var txtDownTotal: TextView
    private lateinit var txtUpSpeed: TextView
    private lateinit var txtUpTotal: TextView
    private lateinit var txtExitNode: TextView
    private lateinit var txtDnsServer: TextView
    private lateinit var txtPeersHeader: TextView
    private lateinit var peerListContainer: LinearLayout

    private val handler = Handler(Looper.getMainLooper())
    private var lastRxBytes: Long = 0
    private var lastTxBytes: Long = 0
    private var lastTimestamp: Long = 0

    private val statusUpdater = object : Runnable {
        override fun run() {
            updateStatus()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#090a0f"))
            isFillViewport = true
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 56, 40, 56)
        }
        scroll.addView(layout)

        // ── Header ──
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, 4)
        }

        val title = TextView(this).apply {
            text = "VANTABLACK"
            textSize = 22f
            setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
            setTextColor(Color.parseColor("#f1f5f9"))
            letterSpacing = 0.15f
        }
        header.addView(title)

        val ver = TextView(this).apply {
            text = "0.8.10"
            textSize = 11f
            setTypeface(Typeface.MONOSPACE)
            setTextColor(Color.parseColor("#64748b"))
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(16, 0, 0, 0) }
            layoutParams = params
        }
        header.addView(ver)
        layout.addView(header)

        val sub = TextView(this).apply {
            text = "Post-Quantum WAN Mesh Router"
            textSize = 12f
            setTextColor(Color.parseColor("#64748b"))
            setPadding(0, 0, 0, 24)
        }
        layout.addView(sub)

        // ── Status Panel ──
        val cardStatus = createCard().apply {
            txtStatus = TextView(context).apply {
                text = if (GhostVpnService.isRunning) "● CONNECTED (TUNNEL ACTIVE)" else "○ DISCONNECTED"
                textSize = 14f
                setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(if (GhostVpnService.isRunning) Color.parseColor("#10b981") else Color.parseColor("#64748b"))
                setPadding(0, 0, 0, 4)
            }
            addView(txtStatus)

            txtMode = TextView(context).apply {
                text = if (GhostVpnService.isRunning) "Route: 0.0.0.0/0, ::/0 (Full Tunnel)" else "Standby"
                textSize = 12f
                setTextColor(Color.parseColor("#94a3b8"))
            }
            addView(txtMode)
        }
        layout.addView(cardStatus)

        // ── Telemetry Grid ──
        val cardTelemetry = createCard().apply {
            addView(createSectionHeader("TRAFFIC & ROUTING"))

            val row1 = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                weightSum = 2f
                setPadding(0, 0, 0, 12)
            }
            val colDown = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(createDimLabel("DOWNLINK"))
                txtDownSpeed = TextView(context).apply {
                    text = "0.0 KB/s"
                    textSize = 15f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#f1f5f9"))
                }
                addView(txtDownSpeed)
                txtDownTotal = TextView(context).apply {
                    text = "0 B (0 pkts)"
                    textSize = 11f
                    setTypeface(Typeface.MONOSPACE)
                    setTextColor(Color.parseColor("#64748b"))
                }
                addView(txtDownTotal)
            }
            val colUp = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(createDimLabel("UPLINK"))
                txtUpSpeed = TextView(context).apply {
                    text = "0.0 KB/s"
                    textSize = 15f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#f1f5f9"))
                }
                addView(txtUpSpeed)
                txtUpTotal = TextView(context).apply {
                    text = "0 B (0 pkts)"
                    textSize = 11f
                    setTypeface(Typeface.MONOSPACE)
                    setTextColor(Color.parseColor("#64748b"))
                }
                addView(txtUpTotal)
            }
            row1.addView(colDown)
            row1.addView(colUp)
            addView(row1)

            // Divider line
            addView(View(context).apply {
                setBackgroundColor(Color.parseColor("#1a1d26"))
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1).apply {
                    setMargins(0, 4, 0, 12)
                }
            })

            val row2 = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                weightSum = 2f
            }
            val colExit = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(createDimLabel("EXIT GATEWAY"))
                txtExitNode = TextView(context).apply {
                    text = "Auto"
                    textSize = 13f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#f1f5f9"))
                }
                addView(txtExitNode)
            }
            val colDns = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(createDimLabel("DNS SERVERS"))
                txtDnsServer = TextView(context).apply {
                    text = "1.1.1.1, 9.9.9.9"
                    textSize = 13f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#f1f5f9"))
                }
                addView(txtDnsServer)
            }
            row2.addView(colExit)
            row2.addView(colDns)
            addView(row2)
        }
        layout.addView(cardTelemetry)

        // ── Mesh Peers Swarm ──
        val cardPeers = createCard().apply {
            txtPeersHeader = createSectionHeader("PEER SESSIONS (0)")
            addView(txtPeersHeader)

            peerListContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }
            addView(peerListContainer)

            btnScanLan = Button(context).apply {
                text = "Scan LAN for Peers"
                textSize = 12f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#cbd5e1"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#151821"))
                    setStroke(1, Color.parseColor("#262b3a"))
                    cornerRadius = 8f
                }
                setPadding(0, 18, 0, 18)
                val params = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(0, 12, 0, 0) }
                layoutParams = params
                setOnClickListener {
                    if (GhostVpnService.isRunning) {
                        GhostVpnService.triggerScan { count ->
                            handler.post {
                                updateStatus()
                                Toast.makeText(this@MainActivity, "Scan finished: $count peer(s)", Toast.LENGTH_SHORT).show()
                            }
                        }
                    } else {
                        Toast.makeText(this@MainActivity, "Connect to mesh first", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            addView(btnScanLan)
        }
        layout.addView(cardPeers)

        // ── Identity Card ──
        val cardId = createCard().apply {
            addView(createSectionHeader("NODE FINGERPRINT"))

            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }

            txtFingerprint = TextView(context).apply {
                text = "—"
                textSize = 14f
                setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(Color.parseColor("#38bdf8"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            row.addView(txtFingerprint)

            btnCopyFp = Button(context).apply {
                text = "Copy"
                textSize = 11f
                setTextColor(Color.parseColor("#cbd5e1"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#151821"))
                    setStroke(1, Color.parseColor("#262b3a"))
                    cornerRadius = 6f
                }
                setPadding(16, 6, 16, 6)
                setOnClickListener {
                    val fp = txtFingerprint.text.toString()
                    if (fp.isNotEmpty() && fp != "—") {
                        val clip = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clip.setPrimaryClip(ClipData.newPlainText("Vantablack Fingerprint", fp))
                        Toast.makeText(this@MainActivity, "Copied", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            row.addView(btnCopyFp)
            addView(row)
        }
        layout.addView(cardId)

        // ── Manual Target Override (Optional) ──
        val prefs = getSharedPreferences("ggn_vpn", MODE_PRIVATE)
        val savedHub = prefs.getString("hub_addr", null)
        editRemoteAddr = EditText(this).apply {
            hint = "192.168.178.27:55225"
            setText(savedHub ?: "192.168.178.27:55225")
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#475569"))
            textSize = 12f
            setTypeface(Typeface.MONOSPACE)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0e1017"))
                setStroke(1, Color.parseColor("#1e2330"))
                cornerRadius = 8f
            }
            setPadding(24, 16, 24, 16)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 4, 0, 12) }
            layoutParams = params
        }
        layout.addView(editRemoteAddr)

        // ── Primary Action Button ──
        btnConnect = Button(this).apply {
            text = if (GhostVpnService.isRunning) "Disconnect" else "Connect"
            textSize = 14f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply {
                setColor(if (GhostVpnService.isRunning) Color.parseColor("#7f1d1d") else Color.parseColor("#1d4ed8"))
                cornerRadius = 8f
            }
            setPadding(0, 28, 0, 28)
            setOnClickListener {
                if (GhostVpnService.isRunning) {
                    stopService(Intent(this@MainActivity, GhostVpnService::class.java))
                    GhostVpnService.isRunning = false
                    updateUiState(false)
                } else {
                    startVpn()
                }
            }
        }
        layout.addView(btnConnect)

        // ── DNS Leak Test Link ──
        btnLeakTest = Button(this).apply {
            text = "Verify on dnsleaktest.com"
            textSize = 12f
            setTextColor(Color.parseColor("#94a3b8"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0e1017"))
                setStroke(1, Color.parseColor("#1e2330"))
                cornerRadius = 8f
            }
            setPadding(0, 20, 0, 20)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 12, 0, 0) }
            layoutParams = params
            setOnClickListener {
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.dnsleaktest.com")))
                } catch (_: Throwable) {
                    Toast.makeText(this@MainActivity, "Open https://www.dnsleaktest.com", Toast.LENGTH_SHORT).show()
                }
            }
        }
        layout.addView(btnLeakTest)

        setContentView(scroll)
        updateStatus()
    }

    override fun onResume() {
        super.onResume()
        handler.post(statusUpdater)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(statusUpdater)
    }

    private fun createCard(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0e1017"))
                setStroke(1, Color.parseColor("#1e2330"))
                cornerRadius = 10f
            }
            setPadding(28, 24, 28, 24)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 14) }
            layoutParams = params
        }
    }

    private fun createSectionHeader(title: String): TextView {
        return TextView(this).apply {
            text = title
            textSize = 10f
            setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
            setTextColor(Color.parseColor("#64748b"))
            letterSpacing = 0.08f
            setPadding(0, 0, 0, 8)
        }
    }

    private fun createDimLabel(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 10f
            setTypeface(Typeface.MONOSPACE)
            setTextColor(Color.parseColor("#64748b"))
        }
    }

    private fun updateStatus() {
        val now = System.currentTimeMillis()
        val dt = if (lastTimestamp > 0) ((now - lastTimestamp) / 1000.0).coerceAtLeast(0.1) else 1.0

        if (GhostVpnService.isRunning) {
            val fp = GhostVpnService.getFingerprint()
            if (fp.isNotEmpty()) txtFingerprint.text = fp

            val peers = GhostVpnService.getPeersCount()
            val totalNodes = if (peers > 0) peers + 1 else 1
            val quorumText = if (totalNodes >= 5) " (Autonomous Quorum)" else ""
            txtPeersHeader.text = "PEER SESSIONS ($peers PEERS, $totalNodes NODES$quorumText)"

            val activeExit = GhostVpnService.getActiveExitNode()
            txtExitNode.text = if (activeExit.isNotEmpty() && activeExit != "auto") activeExit else "Auto"

            val stats = GhostVpnService.getStats()
            val rxPkts = if (stats.isNotEmpty()) stats[0] else 0L
            val txPkts = if (stats.size > 1) stats[1] else 0L

            val currentRxBytes = rxPkts * 576L
            val currentTxBytes = txPkts * 576L

            val rxRate = if (lastRxBytes > 0 && currentRxBytes >= lastRxBytes) (currentRxBytes - lastRxBytes) / dt else 0.0
            val txRate = if (lastTxBytes > 0 && currentTxBytes >= lastTxBytes) (currentTxBytes - lastTxBytes) / dt else 0.0

            lastRxBytes = currentRxBytes
            lastTxBytes = currentTxBytes
            lastTimestamp = now

            txtDownSpeed.text = String.format(Locale.US, "%.1f KB/s", rxRate / 1024.0)
            txtDownTotal.text = formatBytes(currentRxBytes) + " • " + rxPkts + " pkts"

            txtUpSpeed.text = String.format(Locale.US, "%.1f KB/s", txRate / 1024.0)
            txtUpTotal.text = formatBytes(currentTxBytes) + " • " + txPkts + " pkts"

            peerListContainer.removeAllViews()
            val discovered = GhostVpnService.getDiscoveredPeers()
            if (discovered.isEmpty() && peers > 0) {
                peerListContainer.addView(createPeerRow(activeExit, true))
            } else if (discovered.isEmpty()) {
                peerListContainer.addView(TextView(this).apply {
                    text = "Listening for mesh peers..."
                    textSize = 12f
                    setTypeface(Typeface.MONOSPACE)
                    setTextColor(Color.parseColor("#475569"))
                    setPadding(0, 4, 0, 4)
                })
            } else {
                for (peer in discovered) {
                    peerListContainer.addView(createPeerRow(peer, peer == activeExit))
                }
            }

            txtMode.text = "Route: 0.0.0.0/0, ::/0 (Full Tunnel)"
            updateUiState(true)
        } else {
            txtMode.text = "Standby"
            txtDownSpeed.text = "0.0 KB/s"
            txtUpSpeed.text = "0.0 KB/s"
            peerListContainer.removeAllViews()
            peerListContainer.addView(TextView(this).apply {
                text = "Offline"
                textSize = 12f
                setTypeface(Typeface.MONOSPACE)
                setTextColor(Color.parseColor("#475569"))
                setPadding(0, 4, 0, 4)
            })
            updateUiState(false)
        }
    }

    private fun createPeerRow(addr: String, isExit: Boolean): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 4, 0, 4)

            addView(TextView(context).apply {
                text = if (isExit) "● " else "○ "
                textSize = 11f
                setTextColor(if (isExit) Color.parseColor("#10b981") else Color.parseColor("#64748b"))
            })

            addView(TextView(context).apply {
                text = addr
                textSize = 12f
                setTypeface(Typeface.MONOSPACE)
                setTextColor(Color.parseColor("#cbd5e1"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })

            addView(TextView(context).apply {
                text = if (isExit) "[Exit]" else "[Peer]"
                textSize = 11f
                setTypeface(Typeface.MONOSPACE)
                setTextColor(if (isExit) Color.parseColor("#10b981") else Color.parseColor("#475569"))
            })
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1_048_576 -> String.format(Locale.US, "%.1f MB", bytes / 1_048_576.0)
            bytes >= 1024 -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
    }

    private fun updateUiState(connected: Boolean) {
        if (connected) {
            btnConnect.text = "Disconnect"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#7f1d1d"))
                cornerRadius = 8f
            }
            txtStatus.text = "● CONNECTED (TUNNEL ACTIVE)"
            txtStatus.setTextColor(Color.parseColor("#10b981"))
        } else {
            btnConnect.text = "Connect"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#1d4ed8"))
                cornerRadius = 8f
            }
            txtStatus.text = "○ DISCONNECTED"
            txtStatus.setTextColor(Color.parseColor("#64748b"))
        }
    }

    private fun startVpn() {
        val targetAddr = editRemoteAddr.text.toString().trim().ifEmpty { "auto" }
        getSharedPreferences("ggn_vpn", MODE_PRIVATE).edit()
            .putString("hub_addr", if (targetAddr == "auto") "" else targetAddr)
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
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            val targetAddr = editRemoteAddr.text.toString().trim().ifEmpty { "auto" }
            val serviceIntent = Intent(this, GhostVpnService::class.java).apply {
                putExtra(GhostVpnService.EXTRA_HUB_FP, "auto")
                putExtra(GhostVpnService.EXTRA_HUB_ADDR, targetAddr)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(serviceIntent)
            } else {
                startService(serviceIntent)
            }
            GhostVpnService.isRunning = true
            updateUiState(true)
        } else {
            Toast.makeText(this, "VPN permission rejected", Toast.LENGTH_SHORT).show()
        }
    }
}
