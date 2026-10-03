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
    private lateinit var txtTopology: TextView
    private lateinit var txtFingerprint: TextView

    // Live Telemetry UI
    private lateinit var txtDownSpeed: TextView
    private lateinit var txtDownTotal: TextView
    private lateinit var txtUpSpeed: TextView
    private lateinit var txtUpTotal: TextView
    private lateinit var txtExitNode: TextView
    private lateinit var txtExitStatus: TextView
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
            setBackgroundColor(Color.parseColor("#08090c"))
            isFillViewport = true
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 64)
        }
        scroll.addView(layout)

        // ── 1. Top Brand Header ──
        val headerLayout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, 8)
        }

        val title = TextView(this).apply {
            text = "VANTABLACK"
            textSize = 26f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.WHITE)
            letterSpacing = 0.12f
        }
        headerLayout.addView(title)

        val versionBadge = TextView(this).apply {
            text = "v0.8.6 PQC"
            textSize = 10f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#00f0ff"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0f1b29"))
                setStroke(2, Color.parseColor("#1e3a5f"))
                cornerRadius = 16f
            }
            setPadding(20, 6, 20, 6)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(24, 0, 0, 0)
            }
            layoutParams = params
        }
        headerLayout.addView(versionBadge)
        layout.addView(headerLayout)

        val subtitle = TextView(this).apply {
            text = "Post-Quantum Autonomous Mesh Router • Zero-Leak Tunnel"
            textSize = 12f
            setTextColor(Color.parseColor("#8b949e"))
            setPadding(0, 0, 0, 28)
        }
        layout.addView(subtitle)

        // ── 2. Card: Security & Protection Mode ──
        val cardSecurity = createCard().apply {
            txtStatus = TextView(context).apply {
                text = if (GhostVpnService.isRunning) "● ZERO-LEAK TUNNEL ACTIVE" else "○ STANDBY (UNPROTECTED)"
                textSize = 15f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(if (GhostVpnService.isRunning) Color.parseColor("#10b981") else Color.parseColor("#7d8590"))
                setPadding(0, 0, 0, 6)
            }
            addView(txtStatus)

            txtTopology = TextView(context).apply {
                text = if (GhostVpnService.isRunning) "All Traffic Encapsulated into Mesh (0.0.0.0/0)" else "Tap Activate to shield all internet and DNS traffic"
                textSize = 12f
                setTextColor(Color.parseColor("#94a3b8"))
                setPadding(0, 0, 0, 16)
            }
            addView(txtTopology)

            // Security Badges Horizontal Scroll / Layout
            val badgesLayout = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 4, 0, 0)
            }
            badgesLayout.addView(createBadge("ML-KEM-512 (Kyber)", "#0284c7"))
            badgesLayout.addView(createBadge("ChaCha20-Poly1305", "#6366f1"))
            badgesLayout.addView(createBadge("Zero ISP Leak", "#059669"))
            addView(badgesLayout)
        }
        layout.addView(cardSecurity)

        // ── 3. Card: Live Network Telemetry (2x2 Grid) ──
        val cardTelemetry = createCard().apply {
            addView(TextView(context).apply {
                text = "LIVE MESH TELEMETRY"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#64748b"))
                letterSpacing = 0.08f
                setPadding(0, 0, 0, 16)
            })

            // Row 1: Throughput (Download / Upload)
            val row1 = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                weightSum = 2f
                setPadding(0, 0, 0, 16)
            }
            val colDown = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "DOWNLOAD"
                    textSize = 10f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#94a3b8"))
                })
                txtDownSpeed = TextView(context).apply {
                    text = "0.0 KB/s ↓"
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#38bdf8"))
                }
                addView(txtDownSpeed)
                txtDownTotal = TextView(context).apply {
                    text = "0 B (0 pkts)"
                    textSize = 11f
                    setTextColor(Color.parseColor("#64748b"))
                }
                addView(txtDownTotal)
            }
            val colUp = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "UPLOAD"
                    textSize = 10f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#94a3b8"))
                })
                txtUpSpeed = TextView(context).apply {
                    text = "0.0 KB/s ↑"
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#818cf8"))
                }
                addView(txtUpSpeed)
                txtUpTotal = TextView(context).apply {
                    text = "0 B (0 pkts)"
                    textSize = 11f
                    setTextColor(Color.parseColor("#64748b"))
                }
                addView(txtUpTotal)
            }
            row1.addView(colDown)
            row1.addView(colUp)
            addView(row1)

            // Divider
            addView(View(context).apply {
                background = GradientDrawable().apply { setColor(Color.parseColor("#1e293b")) }
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 2).apply {
                    setMargins(0, 4, 0, 16)
                }
            })

            // Row 2: Exit Gateway & Privacy DNS
            val row2 = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                weightSum = 2f
            }
            val colExit = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "ACTIVE EXIT GATEWAY"
                    textSize = 10f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#94a3b8"))
                })
                txtExitNode = TextView(context).apply {
                    text = "Auto (Scanning...)"
                    textSize = 13f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#f1f5f9"))
                }
                addView(txtExitNode)
                txtExitStatus = TextView(context).apply {
                    text = "Round-Robin Egress Pool"
                    textSize = 11f
                    setTextColor(Color.parseColor("#10b981"))
                }
                addView(txtExitStatus)
            }
            val colDns = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "PRIVACY DNS RESOLVER"
                    textSize = 10f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#94a3b8"))
                })
                txtDnsServer = TextView(context).apply {
                    text = "1.1.1.1 + 9.9.9.9"
                    textSize = 13f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#f1f5f9"))
                }
                addView(txtDnsServer)
                val txtDnsShield = TextView(context).apply {
                    text = "Sealed Tunnel (0 ISP Leaks)"
                    textSize = 11f
                    setTextColor(Color.parseColor("#10b981"))
                }
                addView(txtDnsShield)
            }
            row2.addView(colExit)
            row2.addView(colDns)
            addView(row2)
        }
        layout.addView(cardTelemetry)

        // ── 4. Card: Connected Mesh Swarm ──
        val cardSwarm = createCard().apply {
            txtPeersHeader = TextView(context).apply {
                text = "CONNECTED MESH PEERS (0 NODES)"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#64748b"))
                letterSpacing = 0.08f
                setPadding(0, 0, 0, 12)
            }
            addView(txtPeersHeader)

            peerListContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }
            addView(peerListContainer)

            btnScanLan = Button(context).apply {
                text = "🔍 SCAN WI-FI FOR PEERS NOW"
                textSize = 12f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.WHITE)
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#1e293b"))
                    setStroke(2, Color.parseColor("#334155"))
                    cornerRadius = 10f
                }
                setPadding(0, 24, 0, 24)
                val params = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    setMargins(0, 16, 0, 0)
                }
                layoutParams = params
                setOnClickListener {
                    if (GhostVpnService.isRunning) {
                        Toast.makeText(this@MainActivity, "LAN discovery broadcasted! Nodes syncing...", Toast.LENGTH_SHORT).show()
                        GhostVpnService.triggerScan { count ->
                            handler.post {
                                updateStatus()
                                Toast.makeText(this@MainActivity, "Scan complete — $count peer(s) found", Toast.LENGTH_SHORT).show()
                            }
                        }
                    } else {
                        Toast.makeText(this@MainActivity, "Activate Private Mesh first", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            addView(btnScanLan)
        }
        layout.addView(cardSwarm)

        // ── 5. Card: Device Identity & Fingerprint ──
        val cardId = createCard().apply {
            addView(TextView(context).apply {
                text = "DEVICE CRYPTOGRAPHIC IDENTITY"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#64748b"))
                letterSpacing = 0.08f
                setPadding(0, 0, 0, 8)
            })

            val fpRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }

            txtFingerprint = TextView(context).apply {
                text = "Generating identity..."
                textSize = 14f
                setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(Color.parseColor("#00f0ff"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            fpRow.addView(txtFingerprint)

            btnCopyFp = Button(context).apply {
                text = "COPY"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.WHITE)
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#1e293b"))
                    cornerRadius = 8f
                }
                setPadding(20, 8, 20, 8)
                setOnClickListener {
                    val fp = txtFingerprint.text.toString()
                    if (fp.isNotEmpty() && !fp.contains("...")) {
                        val clip = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clip.setPrimaryClip(ClipData.newPlainText("Vantablack Fingerprint", fp))
                        Toast.makeText(this@MainActivity, "Fingerprint copied to clipboard!", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            fpRow.addView(btnCopyFp)
            addView(fpRow)
        }
        layout.addView(cardId)

        // ── 6. Manual Remote Node Override (Optional) ──
        val prefs = getSharedPreferences("ggn_vpn", MODE_PRIVATE)
        editRemoteAddr = EditText(this).apply {
            hint = "Optional Exit Gateway (e.g. 192.168.178.27:55225)"
            setText(prefs.getString("hub_addr", ""))
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#475569"))
            textSize = 12f
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0f172a"))
                setStroke(2, Color.parseColor("#1e293b"))
                cornerRadius = 10f
            }
            setPadding(28, 20, 28, 20)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 8, 0, 16)
            }
            layoutParams = params
        }
        layout.addView(editRemoteAddr)

        // ── 7. Primary Action Button: Connect / Disconnect ──
        btnConnect = Button(this).apply {
            text = if (GhostVpnService.isRunning) "DISCONNECT MESH" else "ENGAGE SECURE MESH TUNNEL"
            textSize = 14f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply {
                setColor(if (GhostVpnService.isRunning) Color.parseColor("#dc2626") else Color.parseColor("#2563eb"))
                cornerRadius = 12f
            }
            setPadding(0, 36, 0, 36)
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

        // ── 8. Direct Zero-Leak Verification Button ──
        btnLeakTest = Button(this).apply {
            text = "🛡️ VERIFY ZERO-LEAK ON DNSLEAKTEST.COM"
            textSize = 12f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#38bdf8"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0c4a6e"))
                setStroke(2, Color.parseColor("#0284c7"))
                cornerRadius = 12f
            }
            setPadding(0, 28, 0, 28)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 24, 0, 0)
            }
            layoutParams = params
            setOnClickListener {
                try {
                    val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.dnsleaktest.com"))
                    startActivity(browserIntent)
                } catch (_: Throwable) {
                    Toast.makeText(this@MainActivity, "Open https://www.dnsleaktest.com in browser", Toast.LENGTH_LONG).show()
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
                setColor(Color.parseColor("#0f172a"))
                setStroke(2, Color.parseColor("#1e293b"))
                cornerRadius = 16f
            }
            setPadding(36, 32, 36, 32)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 0, 0, 20)
            }
            layoutParams = params
        }
    }

    private fun createBadge(label: String, colorHex: String): TextView {
        return TextView(this).apply {
            text = label
            textSize = 10f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply {
                setColor(Color.parseColor(colorHex))
                cornerRadius = 8f
            }
            setPadding(16, 8, 16, 8)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 0, 12, 0)
            }
            layoutParams = params
        }
    }

    private fun updateStatus() {
        val now = System.currentTimeMillis()
        val dt = if (lastTimestamp > 0) ((now - lastTimestamp) / 1000.0).coerceAtLeast(0.1) else 1.0

        if (GhostVpnService.isRunning) {
            val fp = GhostVpnService.getFingerprint()
            if (fp.isNotEmpty()) {
                txtFingerprint.text = fp
            }

            val peers = GhostVpnService.getPeersCount()
            txtPeersHeader.text = "CONNECTED MESH PEERS ($peers NODES)"

            val activeExit = GhostVpnService.getActiveExitNode()
            txtExitNode.text = if (activeExit.isNotEmpty() && activeExit != "auto") activeExit else "Auto (Active)"

            val stats = GhostVpnService.getStats()
            // stats: [rxPackets, txPackets, epoch, txCounter]
            val rxPkts = if (stats.isNotEmpty()) stats[0] else 0L
            val txPkts = if (stats.size > 1) stats[1] else 0L

            // 576 bytes per standard GTF uniform frame
            val currentRxBytes = rxPkts * 576L
            val currentTxBytes = txPkts * 576L

            val rxRate = if (lastRxBytes > 0 && currentRxBytes >= lastRxBytes) {
                (currentRxBytes - lastRxBytes) / dt
            } else 0.0

            val txRate = if (lastTxBytes > 0 && currentTxBytes >= lastTxBytes) {
                (currentTxBytes - lastTxBytes) / dt
            } else 0.0

            lastRxBytes = currentRxBytes
            lastTxBytes = currentTxBytes
            lastTimestamp = now

            txtDownSpeed.text = String.format(Locale.US, "%.1f KB/s ↓", rxRate / 1024.0)
            txtDownTotal.text = formatBytes(currentRxBytes) + " (" + rxPkts + " pkts)"

            txtUpSpeed.text = String.format(Locale.US, "%.1f KB/s ↑", txRate / 1024.0)
            txtUpTotal.text = formatBytes(currentTxBytes) + " (" + txPkts + " pkts)"

            // Update Swarm Peer List
            peerListContainer.removeAllViews()
            val discovered = GhostVpnService.getDiscoveredPeers()
            if (discovered.isEmpty() && peers > 0) {
                peerListContainer.addView(createPeerRow(activeExit, true))
            } else if (discovered.isEmpty()) {
                peerListContainer.addView(TextView(this).apply {
                    text = "Listening for incoming beacons & tracker handshakes..."
                    textSize = 12f
                    setTextColor(Color.parseColor("#64748b"))
                    setPadding(0, 4, 0, 8)
                })
            } else {
                for (peer in discovered) {
                    val isExit = (peer == activeExit)
                    peerListContainer.addView(createPeerRow(peer, isExit))
                }
            }

            txtTopology.text = "All Traffic Encapsulated into Mesh (0.0.0.0/0)"
            updateUiState(true)
        } else {
            txtTopology.text = "Tap Engage to encapsulate all internet & DNS traffic"
            txtDownSpeed.text = "0.0 KB/s ↓"
            txtUpSpeed.text = "0.0 KB/s ↑"
            peerListContainer.removeAllViews()
            peerListContainer.addView(TextView(this).apply {
                text = "Mesh offline. Tap Engage to connect."
                textSize = 12f
                setTextColor(Color.parseColor("#64748b"))
                setPadding(0, 4, 0, 8)
            })
            updateUiState(false)
        }
    }

    private fun createPeerRow(addr: String, isExit: Boolean): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 6, 0, 6)

            addView(TextView(context).apply {
                text = "● "
                textSize = 12f
                setTextColor(if (isExit) Color.parseColor("#10b981") else Color.parseColor("#38bdf8"))
            })

            addView(TextView(context).apply {
                text = addr
                textSize = 12f
                setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(Color.parseColor("#f1f5f9"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })

            addView(TextView(context).apply {
                text = if (isExit) "[Exit Gateway]" else "[Mesh Peer]"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(if (isExit) Color.parseColor("#10b981") else Color.parseColor("#64748b"))
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
            btnConnect.text = "DISCONNECT MESH"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#dc2626"))
                cornerRadius = 12f
            }
            txtStatus.text = "● ZERO-LEAK TUNNEL ACTIVE"
            txtStatus.setTextColor(Color.parseColor("#10b981"))
        } else {
            btnConnect.text = "ENGAGE SECURE MESH TUNNEL"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#2563eb"))
                cornerRadius = 12f
            }
            txtStatus.text = "○ STANDBY (UNPROTECTED)"
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
