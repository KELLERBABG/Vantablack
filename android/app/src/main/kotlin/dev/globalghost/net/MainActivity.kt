package dev.globalghost.net

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
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
    private lateinit var editRemoteAddr: EditText
    private lateinit var btnConnect: Button
    private lateinit var btnScanLan: Button
    private lateinit var txtStatus: TextView
    private lateinit var txtTopology: TextView
    private lateinit var txtFingerprint: TextView
    private val handler = Handler(Looper.getMainLooper())
    private var scanIntervalSecs: Long = 3600 // 1 hour default

    private val statusUpdater = object : Runnable {
        override fun run() {
            updateStatus()
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.parseColor("#0a0c10"))
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(56, 72, 56, 56)
        }
        scroll.addView(layout)

        // Brand Title
        val title = TextView(this).apply {
            text = "VANTABLACK"
            textSize = 24f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.WHITE)
            letterSpacing = 0.08f
            setPadding(0, 0, 0, 8)
        }
        layout.addView(title)

        val subtitle = TextView(this).apply {
            text = "Autonomous Post-Quantum Private Mesh"
            textSize = 13f
            setTextColor(Color.parseColor("#7d8590"))
            setPadding(0, 0, 0, 36)
        }
        layout.addView(subtitle)

        // Card 1: Node Identity
        val cardId = createCard().apply {
            addView(TextView(context).apply {
                text = "THIS DEVICE NODE FINGERPRINT"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#8b949e"))
                letterSpacing = 0.06f
                setPadding(0, 0, 0, 8)
            })

            txtFingerprint = TextView(context).apply {
                text = "Initializing identity..."
                textSize = 14f
                setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(Color.parseColor("#00f0ff"))
            }
            addView(txtFingerprint)
        }
        layout.addView(cardId)

        // Card 2: Mesh Status & Topology
        val cardStatus = createCard().apply {
            txtStatus = TextView(context).apply {
                text = if (GhostVpnService.isRunning) "● PRIVATE MESH ACTIVE (tun0)" else "○ READY TO ENGAGE"
                textSize = 14f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(if (GhostVpnService.isRunning) Color.parseColor("#10b981") else Color.parseColor("#7d8590"))
                setPadding(0, 0, 0, 8)
            }
            addView(txtStatus)

            txtTopology = TextView(context).apply {
                text = "Private Mesh: Standby"
                textSize = 12f
                setTextColor(Color.parseColor("#8b949e"))
            }
            addView(txtTopology)
        }
        layout.addView(cardStatus)

        // Autonomous LAN Discovery Section
        val lblDiscovery = TextView(this).apply {
            text = "AUTONOMOUS LAN DISCOVERY"
            textSize = 11f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#8b949e"))
            letterSpacing = 0.06f
            setPadding(0, 24, 0, 8)
        }
        layout.addView(lblDiscovery)

        // Scan LAN Button
        btnScanLan = Button(this).apply {
            text = "🔍 SCAN LAN FOR PEERS NOW"
            textSize = 13f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#1f2937"))
                setStroke(2, Color.parseColor("#374151"))
                cornerRadius = 12f
            }
            setPadding(0, 28, 0, 28)
            setOnClickListener {
                if (GhostVpnService.isRunning) {
                    val count = GhostVpnService.triggerScan()
                    Toast.makeText(this@MainActivity, "LAN discovery sweep broadcasted! Nodes connecting...", Toast.LENGTH_SHORT).show()
                    updateStatus()
                } else {
                    Toast.makeText(this@MainActivity, "Activate Private Mesh first to scan Wi-Fi", Toast.LENGTH_SHORT).show()
                }
            }
        }
        layout.addView(btnScanLan)

        // Interval selector
        val intervalLayout = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 16, 0, 16)
            gravity = Gravity.CENTER_VERTICAL
        }
        intervalLayout.addView(TextView(this).apply {
            text = "Auto-Scan Interval: "
            textSize = 12f
            setTextColor(Color.parseColor("#8b949e"))
        })

        val btn1h = Button(this).apply {
            text = "1 Hour"
            textSize = 11f
            setTextColor(Color.WHITE)
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#2563eb"))
                cornerRadius = 8f
            }
            setPadding(16, 8, 16, 8)
        }
        val btn4h = Button(this).apply {
            text = "4 Hours"
            textSize = 11f
            setTextColor(Color.parseColor("#8b949e"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#1f2937"))
                cornerRadius = 8f
            }
            setPadding(16, 8, 16, 8)
        }
        btn1h.setOnClickListener {
            scanIntervalSecs = 3600
            btn1h.setTextColor(Color.WHITE)
            btn1h.background = GradientDrawable().apply { setColor(Color.parseColor("#2563eb")); cornerRadius = 8f }
            btn4h.setTextColor(Color.parseColor("#8b949e"))
            btn4h.background = GradientDrawable().apply { setColor(Color.parseColor("#1f2937")); cornerRadius = 8f }
            Toast.makeText(this, "Discovery interval: Every 1 Hour", Toast.LENGTH_SHORT).show()
        }
        btn4h.setOnClickListener {
            scanIntervalSecs = 14400
            btn4h.setTextColor(Color.WHITE)
            btn4h.background = GradientDrawable().apply { setColor(Color.parseColor("#2563eb")); cornerRadius = 8f }
            btn1h.setTextColor(Color.parseColor("#8b949e"))
            btn1h.background = GradientDrawable().apply { setColor(Color.parseColor("#1f2937")); cornerRadius = 8f }
            Toast.makeText(this, "Discovery interval: Every 4 Hours", Toast.LENGTH_SHORT).show()
        }
        intervalLayout.addView(btn1h)
        val spacer = View(this).apply { layoutParams = LinearLayout.LayoutParams(16, 1) }
        intervalLayout.addView(spacer)
        intervalLayout.addView(btn4h)
        layout.addView(intervalLayout)

        // Optional manual peer connect
        val lblManual = TextView(this).apply {
            text = "ADD REMOTE PEER (OPTIONAL IP:PORT)"
            textSize = 11f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#8b949e"))
            letterSpacing = 0.06f
            setPadding(0, 24, 0, 8)
        }
        layout.addView(lblManual)

        val prefs = getSharedPreferences("ggn_vpn", MODE_PRIVATE)
        editRemoteAddr = EditText(this).apply {
            hint = "Auto-discovering via LAN broadcast..."
            setText(prefs.getString("hub_addr", ""))
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#484f58"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#161b22"))
                setStroke(2, Color.parseColor("#30363d"))
                cornerRadius = 12f
            }
            setPadding(32, 24, 32, 24)
        }
        layout.addView(editRemoteAddr)

        // Main Connect Button
        btnConnect = Button(this).apply {
            text = if (GhostVpnService.isRunning) "DISCONNECT MESH" else "ACTIVATE PRIVATE MESH"
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

        val btnParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(0, 48, 0, 0)
        }
        layout.addView(btnConnect, btnParams)

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
                setColor(Color.parseColor("#161b22"))
                setStroke(2, Color.parseColor("#30363d"))
                cornerRadius = 14f
            }
            setPadding(36, 32, 36, 32)
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 0, 0, 24)
            }
            layoutParams = params
        }
    }

    private fun updateStatus() {
        if (GhostVpnService.isRunning) {
            val fp = GhostVpnService.getFingerprint()
            if (fp.isNotEmpty()) {
                txtFingerprint.text = fp
            }
            val peers = GhostVpnService.getPeersCount()
            if (peers >= 5) {
                txtTopology.text = "Autonomous Local Mesh ($peers Nodes) — Local Quorum Active"
                txtTopology.setTextColor(Color.parseColor("#10b981"))
            } else if (peers > 0) {
                txtTopology.text = "WAN Mesh Assisted ($peers Connected Nodes)"
                txtTopology.setTextColor(Color.parseColor("#38bdf8"))
            } else {
                txtTopology.text = "Private Mesh Active — Auto-scanning Wi-Fi for nodes..."
                txtTopology.setTextColor(Color.parseColor("#f59e0b"))
            }
            updateUiState(true)
        } else {
            txtTopology.text = "Standby (Click Activate to join mesh)"
            txtTopology.setTextColor(Color.parseColor("#7d8590"))
            updateUiState(false)
        }
    }

    private fun updateUiState(connected: Boolean) {
        if (connected) {
            btnConnect.text = "DISCONNECT MESH"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#dc2626"))
                cornerRadius = 12f
            }
            txtStatus.text = "● PRIVATE MESH ACTIVE (tun0)"
            txtStatus.setTextColor(Color.parseColor("#10b981"))
        } else {
            btnConnect.text = "ACTIVATE PRIVATE MESH"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#2563eb"))
                cornerRadius = 12f
            }
            txtStatus.text = "○ STANDBY (READY TO ENGAGE)"
            txtStatus.setTextColor(Color.parseColor("#7d8590"))
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
            handler.postDelayed({
                GhostVpnService.triggerScan()
                updateStatus()
            }, 1000)
        } else {
            Toast.makeText(this, "VPN permission rejected", Toast.LENGTH_SHORT).show()
        }
    }
}
