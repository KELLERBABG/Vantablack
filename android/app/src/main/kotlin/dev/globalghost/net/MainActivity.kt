package dev.globalghost.net

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    private val VPN_REQUEST_CODE = 1001
    private lateinit var editHubFp: EditText
    private lateinit var editHubAddr: EditText
    private lateinit var btnConnect: Button
    private lateinit var txtStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(64, 96, 64, 64)
            setBackgroundColor(Color.parseColor("#0a0c10"))
        }

        val title = TextView(this).apply {
            text = "VANTABLACK"
            textSize = 24f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#ffffff"))
            letterSpacing = 0.08f
            setPadding(0, 0, 0, 16)
        }
        layout.addView(title)

        val subtitle = TextView(this).apply {
            text = "Post-Quantum Mesh & Autonomous VPN"
            textSize = 13f
            setTextColor(Color.parseColor("#7d8590"))
            setPadding(0, 0, 0, 48)
        }
        layout.addView(subtitle)

        val lblAddr = TextView(this).apply {
            text = "HUB ENDPOINT (IP:PORT)"
            textSize = 12f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#8b949e"))
            setPadding(0, 0, 0, 8)
        }
        layout.addView(lblAddr)

        val prefs = getSharedPreferences("ggn_vpn", MODE_PRIVATE)
        val initialAddr = intent?.getStringExtra(GhostVpnService.EXTRA_HUB_ADDR)
            ?: prefs.getString("hub_addr", "192.168.178.36:55225")
            ?: "192.168.178.36:55225"
        val initialFp = intent?.getStringExtra(GhostVpnService.EXTRA_HUB_FP)
            ?: prefs.getString("hub_fp", "5fa96851e39ae44b")
            ?: "5fa96851e39ae44b"

        editHubAddr = EditText(this).apply {
            hint = "192.168.178.36:55225"
            setText(initialAddr)
            setTextColor(Color.parseColor("#ffffff"))
            setHintTextColor(Color.parseColor("#484f58"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#161b22"))
                setStroke(2, Color.parseColor("#30363d"))
                cornerRadius = 12f
            }
            setPadding(32, 28, 32, 28)
        }
        layout.addView(editHubAddr)

        val lblFp = TextView(this).apply {
            text = "HUB ED25519 FINGERPRINT (HEX)"
            textSize = 12f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#8b949e"))
            setPadding(0, 32, 0, 8)
        }
        layout.addView(lblFp)

        editHubFp = EditText(this).apply {
            hint = "5fa96851e39ae44b"
            setText(initialFp)
            setTextColor(Color.parseColor("#ffffff"))
            setHintTextColor(Color.parseColor("#484f58"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#161b22"))
                setStroke(2, Color.parseColor("#30363d"))
                cornerRadius = 12f
            }
            setPadding(32, 28, 32, 28)
        }
        layout.addView(editHubFp)

        btnConnect = Button(this).apply {
            text = if (GhostVpnService.isRunning) "DISCONNECT MESH" else "ACTIVATE QUANTUM TUNNEL"
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

        txtStatus = TextView(this).apply {
            text = if (GhostVpnService.isRunning) "● SECURE TUNNEL ACTIVE (tun0)" else "○ READY TO ENGAGE"
            textSize = 13f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(if (GhostVpnService.isRunning) Color.parseColor("#10b981") else Color.parseColor("#7d8590"))
            setPadding(0, 48, 0, 0)
        }
        layout.addView(txtStatus)

        setContentView(layout)
    }

    private fun updateUiState(connected: Boolean) {
        if (connected) {
            btnConnect.text = "DISCONNECT MESH"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#dc2626"))
                cornerRadius = 12f
            }
            txtStatus.text = "● SECURE TUNNEL ACTIVE (tun0)"
            txtStatus.setTextColor(Color.parseColor("#10b981"))
        } else {
            btnConnect.text = "ACTIVATE QUANTUM TUNNEL"
            btnConnect.background = GradientDrawable().apply {
                setColor(Color.parseColor("#2563eb"))
                cornerRadius = 12f
            }
            txtStatus.text = "○ DISCONNECTED"
            txtStatus.setTextColor(Color.parseColor("#7d8590"))
        }
    }

    private fun startVpn() {
        val hubFp = editHubFp.text.toString().trim()
        val hubAddr = editHubAddr.text.toString().trim()
        if (hubFp.isEmpty() || hubAddr.isEmpty()) {
            Toast.makeText(this, "Enter both Hub address and fingerprint", Toast.LENGTH_LONG).show()
            return
        }
        getSharedPreferences("ggn_vpn", MODE_PRIVATE).edit()
            .putString("hub_addr", hubAddr)
            .putString("hub_fp", hubFp)
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
            val hubFp = editHubFp.text.toString().trim()
            val hubAddr = editHubAddr.text.toString().trim()
            val serviceIntent = Intent(this, GhostVpnService::class.java).apply {
                putExtra(GhostVpnService.EXTRA_HUB_FP, hubFp)
                putExtra(GhostVpnService.EXTRA_HUB_ADDR, hubAddr)
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
