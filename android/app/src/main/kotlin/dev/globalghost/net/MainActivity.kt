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
import java.util.Locale

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
    private lateinit var txtExitValue: TextView
    private lateinit var txtExitSub: TextView
    private lateinit var txtRttValue: TextView
    private lateinit var txtRttSub: TextView
    private lateinit var btnUpdateBadge: Button
    private lateinit var txtUpdateStatus: TextView
    private lateinit var btnUpdateAction: TextView
    private lateinit var txtAdblockStatus: TextView
    private lateinit var btnAdblockToggle: TextView
    private var adblockEnabled = true
    private lateinit var txtThreatShieldStatus: TextView
    private lateinit var btnThreatShieldToggle: TextView
    private var threatShieldEnabled = false
    private lateinit var cardThreatPullback: LinearLayout
    private lateinit var threatRecentContainer: LinearLayout
    private val threatAllowlist = mutableSetOf<String>()
    private var lastThreatBlocksKey = ""

    // Real live telemetry views
    private lateinit var txtDownSpeed: TextView
    private lateinit var txtDownTotal: TextView
    private lateinit var txtUpSpeed: TextView
    private lateinit var txtUpTotal: TextView
    private lateinit var txtConnPath: TextView
    private lateinit var txtDnsServer: TextView
    private lateinit var txtHandovers: TextView
    private lateinit var txtFingerprint: TextView
    private lateinit var txtPeersHeader: TextView
    private lateinit var peerListContainer: LinearLayout
    private lateinit var advancedContainer: LinearLayout
    private lateinit var txtAdvancedToggle: TextView

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
            setPadding(dp(22), dp(22), dp(22), dp(28))
        }
        scroll.addView(root)

        // ── Top Bar (Monolith Coal) ──
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(18))
        }

        val title = TextView(this).apply {
            text = "Vantablack"
            textSize = 18f
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

        // ── Center Stage: Machined Brushed-Steel Button + Real Exit / Latency Flanks ──
        val heroSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(0, dp(8), 0, dp(20))
        }

        centerButtonFrame = FrameLayout(this).apply {
            val size = dp(170)
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
                    gravity = Gravity.CENTER_HORIZONTAL
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

        // Interactive Flanks Row: Exit Gateway Picker (left) & Mode + Latency (right)
        val flanksRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            weightSum = 2f
            setPadding(0, dp(18), 0, 0)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val leftFlank = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.START
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0DFFFFFF"))
                setStroke(1, Color.parseColor("#1EFFFFFF"))
                cornerRadius = dp(14).toFloat()
            }
            setPadding(dp(14), dp(12), dp(14), dp(12))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(0, 0, dp(6), 0)
            }
            setOnClickListener { showExitPickerDialog() }
            addView(TextView(context).apply {
                text = "EXIT GATEWAY ▾"
                textSize = 10f
                letterSpacing = 0.12f
                setTextColor(Color.parseColor("#8E8D8A"))
            })
            txtExitValue = TextView(context).apply {
                text = "Auto Mesh"
                textSize = 16f
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                setTypeface(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, dp(3), 0, 0)
            }
            addView(txtExitValue)
            txtExitSub = TextView(context).apply {
                text = "Tap to choose"
                textSize = 11f
                setTextColor(Color.parseColor("#9E9C98"))
            }
            addView(txtExitSub)
        }

        val rightFlank = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.END
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0DFFFFFF"))
                setStroke(1, Color.parseColor("#1EFFFFFF"))
                cornerRadius = dp(14).toFloat()
            }
            setPadding(dp(14), dp(12), dp(14), dp(12))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(dp(6), 0, 0, 0)
            }
            setOnClickListener {
                currentModeIndex = (currentModeIndex + 1) % modes.size
                txtRttValue.text = modes[currentModeIndex]
                txtRttSub.text = modeDescription(modes[currentModeIndex])
                Toast.makeText(this@MainActivity, "${modes[currentModeIndex]}: ${modeDescription(modes[currentModeIndex])}", Toast.LENGTH_SHORT).show()
            }
            addView(TextView(context).apply {
                text = "MODE ↻"
                textSize = 10f
                letterSpacing = 0.12f
                gravity = Gravity.END
                setTextColor(Color.parseColor("#8E8D8A"))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            })
            txtRttValue = TextView(context).apply {
                text = modes[currentModeIndex]
                textSize = 16f
                gravity = Gravity.END
                setTypeface(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, dp(3), 0, 0)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            addView(txtRttValue)
            txtRttSub = TextView(context).apply {
                text = modeDescription(modes[currentModeIndex])
                textSize = 10f
                gravity = Gravity.END
                setTextColor(Color.parseColor("#9E9C98"))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            addView(txtRttSub)
        }

        flanksRow.addView(leftFlank)
        flanksRow.addView(rightFlank)
        heroSection.addView(flanksRow)
        root.addView(heroSection)

        // ── Quick Pairing Pill Dock (+ Scan QR, Invite QR & Paste Link) ──
        val dockRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            weightSum = 3f
            setPadding(dp(6), dp(6), dp(6), dp(6))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#0DFFFFFF"))
                setStroke(1, Color.parseColor("#1AFFFFFF"))
                cornerRadius = dp(999).toFloat()
            }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, dp(14)) }
        }

        val btnScanQr = Button(this).apply {
            text = "+ Scan QR"
            textSize = 11f
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

        val btnInviteQr = Button(this).apply {
            text = "Invite QR"
            textSize = 11f
            isAllCaps = false
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#F4F1EA"))
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#18FFFFFF"))
                cornerRadius = dp(999).toFloat()
            }
            setPadding(0, dp(10), 0, dp(10))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(dp(2), 0, dp(2), 0)
            }
            setOnClickListener { showInviteQrDialog() }
        }

        val btnPasteInvite = Button(this).apply {
            text = "Paste Link"
            textSize = 11f
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
        dockRow.addView(btnInviteQr)
        dockRow.addView(btnPasteInvite)
        root.addView(dockRow)

        // ── Live Traffic & Tunnel Card (Real Telemetry) ──
        val cardTelemetry = createCoalCard().apply {
            addView(createSectionLabel("TRAFFIC & TUNNEL"))

            val speedRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                weightSum = 2f
                setPadding(0, dp(4), 0, dp(12))
            }

            val colDown = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(createDimLabel("DOWNLINK"))
                txtDownSpeed = TextView(context).apply {
                    text = "0 B/s"
                    textSize = 15f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                }
                addView(txtDownSpeed)
                txtDownTotal = TextView(context).apply {
                    text = "0 B • 0 pkts"
                    textSize = 11f
                    setTextColor(Color.parseColor("#8E8D8A"))
                }
                addView(txtDownTotal)
            }

            val colUp = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(createDimLabel("UPLINK"))
                txtUpSpeed = TextView(context).apply {
                    text = "0 B/s"
                    textSize = 15f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                }
                addView(txtUpSpeed)
                txtUpTotal = TextView(context).apply {
                    text = "0 B • 0 pkts"
                    textSize = 11f
                    setTextColor(Color.parseColor("#8E8D8A"))
                }
                addView(txtUpTotal)
            }

            speedRow.addView(colDown)
            speedRow.addView(colUp)
            addView(speedRow)

            // Hairline divider
            addView(View(context).apply {
                setBackgroundColor(Color.parseColor("#14FFFFFF"))
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1).apply {
                    setMargins(0, 0, 0, dp(10))
                }
            })

            val detailRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                weightSum = 3f
            }

            val colPath = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1.1f)
                addView(createDimLabel("PATH"))
                txtConnPath = TextView(context).apply {
                    text = "Standby"
                    textSize = 12f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                }
                addView(txtConnPath)
            }

            val colDns = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1.2f)
                addView(createDimLabel("DNS"))
                txtDnsServer = TextView(context).apply {
                    text = "Auto (10.66.0.1)"
                    textSize = 12f
                    maxLines = 1
                    ellipsize = android.text.TextUtils.TruncateAt.END
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                }
                addView(txtDnsServer)
            }

            val colHandover = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.7f)
                addView(createDimLabel("HANDOVERS"))
                txtHandovers = TextView(context).apply {
                    text = "0"
                    textSize = 12f
                    setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                }
                addView(txtHandovers)
            }

            detailRow.addView(colPath)
            detailRow.addView(colDns)
            detailRow.addView(colHandover)
            addView(detailRow)
        }
        root.addView(cardTelemetry)

        // ── Linked Devices Card ──
        val cardPeers = createCoalCard().apply {
            val topRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 0, 0, dp(10))
            }
            txtPeersHeader = TextView(context).apply {
                text = "Linked Devices (0)"
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

        // ── Node Identity & Advanced Gateway Overrides ──
        val prefs = getSharedPreferences("ggn_vpn", MODE_PRIVATE)
        val savedHub = prefs.getString("hub_addr", null)
        val savedDns = prefs.getString("dns_server", null)

        val cardIdentity = createCoalCard().apply {
            addView(createSectionLabel("NODE FINGERPRINT"))
            val idRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 0, 0, dp(10))
            }
            txtFingerprint = TextView(context).apply {
                text = "—"
                textSize = 13f
                setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            idRow.addView(txtFingerprint)

            val btnCopyFp = TextView(context).apply {
                text = "Copy"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(12), dp(5), dp(12), dp(5))
                setOnClickListener {
                    val fp = txtFingerprint.text.toString()
                    if (fp.isNotEmpty() && fp != "—") {
                        val clip = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clip.setPrimaryClip(ClipData.newPlainText("Vantablack Fingerprint", fp))
                        Toast.makeText(this@MainActivity, "Fingerprint copied", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            idRow.addView(btnCopyFp)
            addView(idRow)

            // Expandable Gateway & DNS Overrides
            txtAdvancedToggle = TextView(context).apply {
                text = "Gateway & DNS Overrides ▾"
                textSize = 11f
                setTextColor(Color.parseColor("#9E9C98"))
                setPadding(0, dp(4), 0, dp(4))
                setOnClickListener {
                    val show = advancedContainer.visibility != View.VISIBLE
                    advancedContainer.visibility = if (show) View.VISIBLE else View.GONE
                    text = if (show) "Gateway & DNS Overrides ▴" else "Gateway & DNS Overrides ▾"
                }
            }
            addView(txtAdvancedToggle)

            advancedContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                visibility = View.GONE
                setPadding(0, dp(8), 0, 0)

                editRemoteAddr = EditText(context).apply {
                    hint = "Exit Gateway: Auto (or Hub IP:Port)"
                    setText(savedHub ?: "")
                    setTextColor(Color.parseColor("#F4F1EA"))
                    setHintTextColor(Color.parseColor("#6E6D6A"))
                    textSize = 12f
                    setTypeface(Typeface.MONOSPACE)
                    background = GradientDrawable().apply {
                        setColor(Color.parseColor("#14000000"))
                        setStroke(1, Color.parseColor("#22FFFFFF"))
                        cornerRadius = dp(10).toFloat()
                    }
                    setPadding(dp(14), dp(10), dp(14), dp(10))
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { setMargins(0, 0, 0, dp(8)) }
                }
                addView(editRemoteAddr)

                editDnsServer = EditText(context).apply {
                    hint = "DNS Server: Auto via Exit Hub (or custom IP)"
                    setText(savedDns ?: "")
                    setTextColor(Color.parseColor("#F4F1EA"))
                    setHintTextColor(Color.parseColor("#6E6D6A"))
                    textSize = 12f
                    setTypeface(Typeface.MONOSPACE)
                    background = GradientDrawable().apply {
                        setColor(Color.parseColor("#14000000"))
                        setStroke(1, Color.parseColor("#22FFFFFF"))
                        cornerRadius = dp(10).toFloat()
                    }
                    setPadding(dp(14), dp(10), dp(14), dp(10))
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { setMargins(0, 0, 0, dp(10)) }
                }
                addView(editDnsServer)

                val toolsRow = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    weightSum = 2f
                }
                val btnLeak = TextView(context).apply {
                    text = "DNS Leak Test ↗"
                    textSize = 11f
                    gravity = Gravity.CENTER
                    setTextColor(Color.parseColor("#F4F1EA"))
                    background = GradientDrawable().apply {
                        setColor(Color.parseColor("#14FFFFFF"))
                        cornerRadius = dp(999).toFloat()
                    }
                    setPadding(0, dp(8), 0, dp(8))
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                        setMargins(0, 0, dp(4), 0)
                    }
                    setOnClickListener {
                        try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.dnsleaktest.com"))) } catch (_: Throwable) {}
                    }
                }
                val btnRepo = TextView(context).apply {
                    text = "GitHub Repo ↗"
                    textSize = 11f
                    gravity = Gravity.CENTER
                    setTextColor(Color.parseColor("#F4F1EA"))
                    background = GradientDrawable().apply {
                        setColor(Color.parseColor("#14FFFFFF"))
                        cornerRadius = dp(999).toFloat()
                    }
                    setPadding(0, dp(8), 0, dp(8))
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                        setMargins(dp(4), 0, 0, 0)
                    }
                    setOnClickListener {
                        try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/KELLERBABG/Vantablack"))) } catch (_: Throwable) {}
                    }
                }
                toolsRow.addView(btnLeak)
                toolsRow.addView(btnRepo)
                addView(toolsRow)
            }
            addView(advancedContainer)
        }
        root.addView(cardIdentity)

        // ── Ad & Tracker Shield Card (Works Even Without Mesh) ──
        adblockEnabled = prefs.getBoolean("adblock_enabled", true)
        try { GhostCore.setAdblockEnabled(adblockEnabled) } catch (_: Throwable) {}
        val cardAdblock = createCoalCard().apply {
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val textCol = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "Block Ads & Trackers"
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                addView(TextView(context).apply {
                    text = "Stops ads and tracking scripts before they load"
                    textSize = 12.5f
                    setTextColor(Color.parseColor("#B0B5BC"))
                    setPadding(0, dp(3), 0, 0)
                })
                txtAdblockStatus = TextView(context).apply {
                    text = if (adblockEnabled) "Active • 0 ads blocked" else "Paused"
                    textSize = 12f
                    setTextColor(Color.parseColor("#9E9C98"))
                    setPadding(0, dp(3), 0, 0)
                }
                addView(txtAdblockStatus)
            }
            row.addView(textCol)

            btnAdblockToggle = TextView(context).apply {
                text = if (adblockEnabled) "On" else "Off"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(if (adblockEnabled) Color.parseColor("#0C0D0F") else Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(if (adblockEnabled) Color.parseColor("#F4F1EA") else Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(16), dp(9), dp(16), dp(9))
            }
            row.addView(btnAdblockToggle)
            setOnClickListener {
                adblockEnabled = !adblockEnabled
                prefs.edit().putBoolean("adblock_enabled", adblockEnabled).apply()
                try { GhostCore.setAdblockEnabled(adblockEnabled) } catch (_: Throwable) {}
                btnAdblockToggle.text = if (adblockEnabled) "On" else "Off"
                btnAdblockToggle.setTextColor(if (adblockEnabled) Color.parseColor("#0C0D0F") else Color.parseColor("#F4F1EA"))
                btnAdblockToggle.background = GradientDrawable().apply {
                    setColor(if (adblockEnabled) Color.parseColor("#F4F1EA") else Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                updateStatus()
            }
            addView(row)
        }
        root.addView(cardAdblock)

        // ── Threat / Malware Shield Card ──
        threatShieldEnabled = prefs.getBoolean("threat_shield_enabled", false)
        threatAllowlist.clear()
        prefs.getStringSet("threat_shield_allowlist", emptySet())?.let { saved ->
            threatAllowlist.addAll(saved)
        }
        try {
            GhostCore.setThreatShieldEnabled(threatShieldEnabled)
            for (d in threatAllowlist) {
                GhostCore.allowThreatShieldDomain(d)
            }
        } catch (_: Throwable) {}

        val cardThreatShield = createCoalCard().apply {
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val textCol = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "Malware & Scam Protection"
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                addView(TextView(context).apply {
                    text = "Blocks known phishing, scam, and malware websites"
                    textSize = 12.5f
                    setTextColor(Color.parseColor("#B0B5BC"))
                    setPadding(0, dp(3), 0, 0)
                })
                txtThreatShieldStatus = TextView(context).apply {
                    text = if (threatShieldEnabled) "Active • 0 threats blocked" else "Paused"
                    textSize = 12f
                    setTextColor(Color.parseColor("#9E9C98"))
                    setPadding(0, dp(3), 0, 0)
                }
                addView(txtThreatShieldStatus)
            }
            row.addView(textCol)

            btnThreatShieldToggle = TextView(context).apply {
                text = if (threatShieldEnabled) "On" else "Off"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(if (threatShieldEnabled) Color.parseColor("#0C0D0F") else Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(if (threatShieldEnabled) Color.parseColor("#F4F1EA") else Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(16), dp(9), dp(16), dp(9))
            }
            row.addView(btnThreatShieldToggle)
            setOnClickListener {
                threatShieldEnabled = !threatShieldEnabled
                prefs.edit().putBoolean("threat_shield_enabled", threatShieldEnabled).apply()
                try { GhostCore.setThreatShieldEnabled(threatShieldEnabled) } catch (_: Throwable) {}
                btnThreatShieldToggle.text = if (threatShieldEnabled) "On" else "Off"
                btnThreatShieldToggle.setTextColor(if (threatShieldEnabled) Color.parseColor("#0C0D0F") else Color.parseColor("#F4F1EA"))
                btnThreatShieldToggle.background = GradientDrawable().apply {
                    setColor(if (threatShieldEnabled) Color.parseColor("#F4F1EA") else Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                updateStatus()
            }
            addView(row)
        }
        root.addView(cardThreatShield)

        // ── Threat Shield Pullback & Whitelist Card ──
        cardThreatPullback = createCoalCard().apply {
            visibility = View.GONE
            addView(TextView(context).apply {
                text = "Threat Shield Pullback & Whitelist"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#E05A47"))
            })
            addView(TextView(context).apply {
                text = "Blocked malicious destinations — tap Whitelist if flagged by mistake"
                textSize = 11f
                setTextColor(Color.parseColor("#9E9C98"))
                setPadding(0, dp(2), 0, dp(8))
            })
            threatRecentContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }
            addView(threatRecentContainer)
        }
        root.addView(cardThreatPullback)

        // ── Operating Regime & QEL Parity Card ──
        val regimes = arrayOf("fast", "shielded", "ghost", "vantablack")
        var activeRegime = prefs.getString("regime", "ghost") ?: "ghost"
        if (!regimes.contains(activeRegime)) activeRegime = "ghost"
        var qelEnabled = prefs.getBoolean("qel_enabled", true)
        try {
            GhostCore.setRegime(activeRegime)
            GhostCore.setQelEnabled(qelEnabled)
        } catch (_: Throwable) {}

        val cardRegimeQel = createCoalCard().apply {
            lateinit var pillRegime: TextView

            val rRow = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val rCol = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "Privacy Regime"
                    textSize = 14f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                addView(TextView(context).apply {
                    text = "Tap to cycle Fast / Shielded / Ghost / Vantablack"
                    textSize = 11f
                    setTextColor(Color.parseColor("#9AA0A6"))
                })
            }
            pillRegime = TextView(context).apply {
                text = activeRegime.replaceFirstChar { it.uppercase() }
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#0C0D0F"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#F4F1EA"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(12), dp(6), dp(12), dp(6))
            }
            rRow.addView(rCol)
            rRow.addView(pillRegime)
            rRow.setOnClickListener {
                val nextIdx = (regimes.indexOf(activeRegime) + 1) % regimes.size
                activeRegime = regimes[nextIdx]
                prefs.edit().putString("regime", activeRegime).apply()
                try { GhostCore.setRegime(activeRegime) } catch (_: Throwable) {}
                pillRegime.text = activeRegime.replaceFirstChar { it.uppercase() }
            }
            addView(rRow)
        }
        root.addView(cardRegimeQel)

        // ── Split-Tunnel (App Bypass) Card ──
        val cardSplitTunnel = createCoalCard().apply {
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            lateinit var txtSplitSub: TextView
            fun countBypass(): Int {
                val raw = prefs.getString("split_tunnel_packages", "") ?: ""
                return raw.split(",", "\n", ";", " ").count { it.trim().isNotEmpty() }
            }
            val col = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "Split Tunnel (App Bypass)"
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                txtSplitSub = TextView(context).apply {
                    val c = countBypass()
                    text = if (c == 0) "All apps routed through tunnel (tap Edit to exclude apps)" else "$c app(s) bypassed (applies on reconnect)"
                    textSize = 12.5f
                    setTextColor(Color.parseColor("#B0B5BC"))
                    setPadding(0, dp(3), 0, 0)
                }
                addView(txtSplitSub)
            }
            val btnEdit = TextView(context).apply {
                text = "Edit"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(16), dp(9), dp(16), dp(9))
            }
            row.addView(col)
            row.addView(btnEdit)
            setOnClickListener {
                val input = EditText(context).apply {
                    hint = "com.example.app, org.example.bank"
                    setText(prefs.getString("split_tunnel_packages", "") ?: "")
                }
                android.app.AlertDialog.Builder(context)
                    .setTitle("Bypassed App Packages")
                    .setMessage("Comma-separated Android package IDs excluded from the VPN tunnel:")
                    .setView(input)
                    .setPositiveButton("Save") { _, _ ->
                        prefs.edit().putString("split_tunnel_packages", input.text.toString().trim()).apply()
                        val c = countBypass()
                        txtSplitSub.text = if (c == 0) "All apps routed through tunnel" else "$c app(s) bypassed (applies on reconnect)"
                    }
                    .setNegativeButton("Cancel", null)
                    .show()
            }
            addView(row)
        }
        root.addView(cardSplitTunnel)

        // ── X-Ray Privacy Check Card ──
        val cardXray = createCoalCard().apply {
            lateinit var txtXrayHeadline: TextView
            lateinit var txtXrayClaim: TextView
            lateinit var txtXrayDetails: TextView
            fun refreshXrayCard(showDialog: Boolean = false) {
                try {
                    val raw = GhostCore.getXrayJson(GhostVpnService.activePtr)
                    val obj = org.json.JSONObject(raw)
                    val headline = obj.optString("headline", "X-Ray ready")
                    val regime = obj.optString("regime", "ghost")
                    val invs = obj.optJSONArray("invariants")
                    val obs = obj.optJSONArray("observations")
                    val formal = obj.optJSONObject("formal")

                    val sb = StringBuilder()
                    var passCount = 0
                    val totalCount = invs?.length() ?: 0
                    val humanTitle = mapOf(
                        "pq_hybrid_kem" to "Quantum-Safe Encryption",
                        "dns_leak_guard" to "DNS Leak Protection",
                        "frame_uniformity" to "Packet Size Masking (576 B)",
                        "multi_hop_circuit" to "3-Hop Onion Anonymity",
                        "asn_diversity" to "Independent Network Providers",
                        "racs_cover_tx" to "Decoy Cover Traffic",
                        "chronos_pacing" to "Timing Analysis Defense",
                        "nonce_echo_hops" to "Multi-Hop Return Integrity",
                        "lightcone_bound" to "Physical Distance Proof"
                    )
                    if (invs != null && invs.length() > 0) {
                        for (i in 0 until invs.length()) {
                            val item = invs.getJSONObject(i)
                            val id = item.optString("id", "check")
                            val state = item.optString("state", "unmeasured")
                            val detail = item.optString("detail", "")
                            val tag = when (state.lowercase()) {
                                "verified", "proven", "ok" -> { passCount++; "[PASS]" }
                                "broken", "violated", "failed" -> "[FAIL]"
                                else -> "[WAIT]"
                            }
                            sb.append("$tag ${humanTitle[id] ?: id} — $detail\n")
                        }
                    }
                    txtXrayHeadline.text = if (totalCount > 0) "Privacy Check: $passCount/$totalCount active" else headline
                    txtXrayClaim.text = "Regime: $regime • Tap Inspect for observer views & proofs"
                    txtXrayDetails.text = sb.toString().trim().ifEmpty { "No checks reported yet" }
                    txtXrayDetails.visibility = View.VISIBLE

                    if (showDialog) {
                        val full = StringBuilder()
                        full.append("Protection: $passCount of $totalCount checks active (Regime: $regime)\n\n")
                        if (invs != null && invs.length() > 0) {
                            full.append("── SECURITY CHECKS (${invs.length()}) ──\n")
                            for (i in 0 until invs.length()) {
                                val item = invs.getJSONObject(i)
                                val id = item.optString("id")
                                val st = item.optString("state")
                                val tag = if (st == "verified" || st == "proven") "[PASS]" else if (st == "failed") "[FAIL]" else "[WAIT]"
                                full.append("$tag ${humanTitle[id] ?: id}\n  ${item.optString("detail")}\n")
                            }
                            full.append("\n")
                        }
                        if (obs != null && obs.length() > 0) {
                            full.append("── OBSERVER VIEWS ──\n")
                            for (i in 0 until obs.length()) {
                                val o = obs.getJSONObject(i)
                                full.append("• ${o.optString("observer")}\n")
                                val sees = o.optJSONArray("sees")
                                val hides = o.optJSONArray("does_not_see")
                                if (sees != null) full.append("  Sees: ${sees.join(", ").replace("\"", "")}\n")
                                if (hides != null) full.append("  Hidden: ${hides.join(", ").replace("\"", "")}\n")
                            }
                            full.append("\n")
                        }
                        if (formal != null) {
                            full.append("── FORMAL PROOFS ──\nProVerif ${formal.optString("proverif")} • ${formal.optInt("models")} models • holds=${formal.optBoolean("all_queries_hold")}\n")
                        }
                        android.app.AlertDialog.Builder(context)
                            .setTitle("X-Ray Truth Ledger")
                            .setMessage(full.toString().trim())
                            .setPositiveButton("Close", null)
                            .show()
                    }
                } catch (_: Throwable) {
                    txtXrayHeadline.text = "X-Ray Privacy Check"
                    txtXrayClaim.text = "Tap Inspect to see all 9 checks & what ISP / Guard / Website see"
                    txtXrayDetails.visibility = View.GONE
                }
            }
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val col = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                txtXrayHeadline = TextView(context).apply {
                    text = "X-Ray Privacy Check"
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                }
                txtXrayClaim = TextView(context).apply {
                    text = "Shows all 9 cryptographic & observer checks (ISP, Guard, Website)"
                    textSize = 12.5f
                    setTextColor(Color.parseColor("#B0B5BC"))
                    setPadding(0, dp(3), 0, 0)
                }
                addView(txtXrayHeadline)
                addView(txtXrayClaim)
            }
            val btnCheck = TextView(context).apply {
                text = "Inspect"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(16), dp(9), dp(16), dp(9))
            }
            row.addView(col)
            row.addView(btnCheck)
            addView(row)

            txtXrayDetails = TextView(context).apply {
                textSize = 12f
                setTextColor(Color.parseColor("#9E9C98"))
                setPadding(0, dp(10), 0, 0)
                visibility = View.GONE
            }
            addView(txtXrayDetails)
            setOnClickListener { refreshXrayCard(showDialog = true) }
        }
        root.addView(cardXray)

        // ── Experimental Dropdown Card ──
        val expSpecs = listOf(
            Triple("exp_pow_shield", "Flood Shield", "Requires a quick puzzle from new peers during traffic floods"),
            Triple("exp_dtn_reconcile", "Offline Sync", "Syncs missed messages automatically after you come back online"),
            Triple("exp_universal_tunnel", "App Port Tunnel", "Forwards non-proxy apps over the mesh via a local port"),
            Triple("exp_collective_defense", "Shared Threat Signals", "Shares anonymous drop stats so peers route around bad links"),
            Triple("exp_rendezvous", "Serverless Discovery", "Finds peers without central seed servers (uses more battery)"),
            Triple("exp_diffusion", "Emergency Broadcast", "Floods traffic across nearby peers if routing breaks (high data use)")
        )
        for ((k, _, _) in expSpecs) {
            try { GhostCore.setExperimentalFlag(k, prefs.getBoolean(k, false)) } catch (_: Throwable) {}
        }
        val cardExperimental = createCoalCard().apply {
            var expanded = false
            lateinit var bodyContainer: LinearLayout
            lateinit var pillArrow: TextView

            val header = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val hCol = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(context).apply {
                    text = "Experimental"
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                addView(TextView(context).apply {
                    text = "Opt-in mesh capabilities (off by default)"
                    textSize = 12.5f
                    setTextColor(Color.parseColor("#B0B5BC"))
                    setPadding(0, dp(3), 0, 0)
                })
            }
            pillArrow = TextView(context).apply {
                text = "Opt-in ▾"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(16), dp(9), dp(16), dp(9))
            }
            header.addView(hCol)
            header.addView(pillArrow)
            addView(header)

            bodyContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
                visibility = View.GONE
                setPadding(0, dp(10), 0, 0)
            }
            bodyContainer.addView(TextView(context).apply {
                text = "Learn more in the documentation ↗"
                textSize = 11f
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, 0, 0, dp(10))
                setOnClickListener {
                    startActivity(Intent(
                        Intent.ACTION_VIEW,
                        Uri.parse("https://github.com/KELLERBABG/Vantablack/blob/main/docs/EXPERIMENTAL_FEATURES.md")
                    ))
                }
            })

            for ((key, title, desc) in expSpecs) {
                var on = prefs.getBoolean(key, false)
                lateinit var pill: TextView
                val itemRow = LinearLayout(context).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(0, dp(6), 0, dp(6))
                }
                val itemCol = LinearLayout(context).apply {
                    orientation = LinearLayout.VERTICAL
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                    addView(TextView(context).apply {
                        text = title
                        textSize = 15f
                        setTypeface(Typeface.DEFAULT_BOLD)
                        setTextColor(Color.parseColor("#F4F1EA"))
                    })
                    addView(TextView(context).apply {
                        text = desc
                        textSize = 12.5f
                        setTextColor(Color.parseColor("#B0B5BC"))
                        setPadding(0, dp(2), 0, 0)
                    })
                }
                pill = TextView(context).apply {
                    text = if (on) "On" else "Off"
                    textSize = 13f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(if (on) Color.parseColor("#0C0D0F") else Color.parseColor("#F4F1EA"))
                    background = GradientDrawable().apply {
                        setColor(if (on) Color.parseColor("#F4F1EA") else Color.parseColor("#18FFFFFF"))
                        cornerRadius = dp(999).toFloat()
                    }
                    setPadding(dp(16), dp(8), dp(16), dp(8))
                }
                itemRow.addView(itemCol)
                itemRow.addView(pill)
                itemRow.setOnClickListener {
                    on = !on
                    prefs.edit().putBoolean(key, on).apply()
                    try { GhostCore.setExperimentalFlag(key, on) } catch (_: Throwable) {}
                    pill.text = if (on) "On" else "Off"
                    pill.setTextColor(if (on) Color.parseColor("#0C0D0F") else Color.parseColor("#F4F1EA"))
                    pill.background = GradientDrawable().apply {
                        setColor(if (on) Color.parseColor("#F4F1EA") else Color.parseColor("#18FFFFFF"))
                        cornerRadius = dp(999).toFloat()
                    }
                }
                bodyContainer.addView(itemRow)
            }

            header.setOnClickListener {
                expanded = !expanded
                bodyContainer.visibility = if (expanded) View.VISIBLE else View.GONE
                pillArrow.text = if (expanded) "Opt-in ▴" else "Opt-in ▾"
            }
            addView(bodyContainer)
        }
        root.addView(cardExperimental)

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
                    textSize = 16f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                txtUpdateStatus = TextView(context).apply {
                    text = "Vantablack v$currentVerName is installed"
                    textSize = 12.5f
                    setTextColor(Color.parseColor("#B0B5BC"))
                    setPadding(0, dp(3), 0, 0)
                }
                addView(txtUpdateStatus)
            }
            row.addView(textCol)

            btnUpdateAction = TextView(context).apply {
                text = "Check"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#18FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(16), dp(9), dp(16), dp(9))
            }
            row.addView(btnUpdateAction)
            setOnClickListener { triggerImmediateUpdate() }
            addView(row)
        }
        root.addView(cardUpdate)

        // ── 4-Tab Bottom Navigation (Home / Devices / Privacy / Settings) ──
        val homeViews = listOf<View>(heroSection, dockRow, cardTelemetry)
        val devicesViews = listOf<View>(cardPeers)
        val privacyViews = listOf<View>(cardXray)
        val settingsViews = listOf<View>(
            cardAdblock, cardThreatShield, cardThreatPullback,
            cardRegimeQel, cardSplitTunnel, cardExperimental, cardIdentity, cardUpdate
        )
        val tabGroups = listOf(homeViews, devicesViews, privacyViews, settingsViews)
        val tabLabels = listOf("Home", "Devices", "Privacy", "Settings")
        val tabButtons = mutableListOf<TextView>()
        var activeTab = 0

        fun selectTab(idx: Int) {
            activeTab = idx
            tabGroups.forEachIndexed { i, views ->
                val vis = if (i == idx) View.VISIBLE else View.GONE
                views.forEach { v ->
                    if (v === cardThreatPullback && vis == View.VISIBLE) {
                        // Preserve pullback conditional visibility
                    } else {
                        v.visibility = vis
                    }
                }
            }
            tabButtons.forEachIndexed { i, btn ->
                val on = i == idx
                btn.setTextColor(if (on) Color.parseColor("#0C0D0F") else Color.parseColor("#9E9C98"))
                btn.background = GradientDrawable().apply {
                    setColor(if (on) Color.parseColor("#F4F1EA") else Color.TRANSPARENT)
                    cornerRadius = dp(999).toFloat()
                }
            }
            scroll.scrollTo(0, 0)
            if (idx == 2) {
                cardXray.performClick()
            }
        }

        val outer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0C0D0F"))
        }
        scroll.layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            0,
            1f
        )
        outer.addView(scroll)

        val bottomBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            weightSum = 4f
            setBackgroundColor(Color.parseColor("#111317"))
            setPadding(dp(10), dp(10), dp(10), dp(14))
        }
        tabLabels.forEachIndexed { idx, label ->
            val btn = TextView(this).apply {
                text = label
                textSize = 13f
                gravity = Gravity.CENTER
                setTypeface(Typeface.DEFAULT_BOLD)
                setPadding(dp(8), dp(10), dp(8), dp(10))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    setMargins(dp(3), 0, dp(3), 0)
                }
                setOnClickListener { selectTab(idx) }
            }
            tabButtons.add(btn)
            bottomBar.addView(btn)
        }
        outer.addView(bottomBar)
        selectTab(0)

        setContentView(outer)
        updateStatus()

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
            setPadding(dp(18), dp(15), dp(18), dp(15))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, dp(12)) }
        }
    }

    private fun createSectionLabel(label: String): TextView {
        return TextView(this).apply {
            text = label
            textSize = 10f
            letterSpacing = 0.12f
            setTypeface(Typeface.DEFAULT_BOLD)
            setTextColor(Color.parseColor("#787774"))
            setPadding(0, 0, 0, dp(8))
        }
    }

    private fun createDimLabel(label: String): TextView {
        return TextView(this).apply {
            text = label
            textSize = 10f
            letterSpacing = 0.08f
            setTextColor(Color.parseColor("#787774"))
        }
    }

    private fun updateThreatPullbackUi() {
        val raw = try { GhostCore.getThreatShieldJson() } catch (_: Throwable) { "" }
        if (raw.isEmpty()) {
            cardThreatPullback.visibility = View.GONE
            return
        }
        val arr = try {
            org.json.JSONObject(raw).optJSONArray("recent")
        } catch (_: Throwable) {
            null
        }
        if (arr == null || arr.length() == 0) {
            cardThreatPullback.visibility = View.GONE
            lastThreatBlocksKey = ""
            return
        }
        cardThreatPullback.visibility = View.VISIBLE

        val items = mutableListOf<Pair<String, String>>()
        val seen = HashSet<String>()
        for (i in 0 until arr.length()) {
            val obj = arr.optJSONObject(i) ?: continue
            val target = obj.optString("target", "").trim()
            val kind = obj.optString("kind", "threat").trim()
            if (target.isNotEmpty() && seen.add(target)) {
                items.add(target to kind)
            }
        }
        val key = items.joinToString("|") { (t, k) -> "$t:$k:${threatAllowlist.contains(t)}" }
        if (key == lastThreatBlocksKey) return
        lastThreatBlocksKey = key

        threatRecentContainer.removeAllViews()
        for ((target, kind) in items) {
            val isAllowed = threatAllowlist.contains(target)
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(6), 0, dp(6))
            }
            val infoCol = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                addView(TextView(this@MainActivity).apply {
                    text = target
                    textSize = 12f
                    setTypeface(Typeface.DEFAULT_BOLD)
                    setTextColor(Color.parseColor("#F4F1EA"))
                })
                addView(TextView(this@MainActivity).apply {
                    text = "Blocked ($kind)"
                    textSize = 10f
                    setTextColor(Color.parseColor("#9E9C98"))
                })
            }
            row.addView(infoCol)

            val btnWhitelist = TextView(this).apply {
                text = if (isAllowed) "Allowed" else "Whitelist"
                textSize = 11f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(if (isAllowed) Color.parseColor("#9E9C98") else Color.parseColor("#0C0D0F"))
                background = GradientDrawable().apply {
                    setColor(if (isAllowed) Color.parseColor("#18FFFFFF") else Color.parseColor("#F4F1EA"))
                    cornerRadius = dp(999).toFloat()
                }
                setPadding(dp(12), dp(6), dp(12), dp(6))
                if (!isAllowed) {
                    setOnClickListener {
                        threatAllowlist.add(target)
                        getSharedPreferences("ggn_vpn", MODE_PRIVATE)
                            .edit()
                            .putStringSet("threat_shield_allowlist", threatAllowlist.toSet())
                            .apply()
                        try { GhostCore.allowThreatShieldDomain(target) } catch (_: Throwable) {}
                        Toast.makeText(this@MainActivity, "Whitelisted $target", Toast.LENGTH_SHORT).show()
                        lastThreatBlocksKey = ""
                        updateThreatPullbackUi()
                    }
                }
            }
            row.addView(btnWhitelist)
            threatRecentContainer.addView(row)
        }
    }

    private fun updateStatus() {
        val now = System.currentTimeMillis()
        val dt = if (lastTimestamp > 0) ((now - lastTimestamp) / 1000.0).coerceAtLeast(0.1) else 1.0

        val adsBlocked = try { GhostCore.getAdsBlocked() } catch (_: Throwable) { 0L }
        txtAdblockStatus.text = if (adblockEnabled) "Active • $adsBlocked ads blocked" else "Paused"

        val threatsBlocked = try { GhostCore.getThreatShieldBlocked() } catch (_: Throwable) { 0L }
        txtThreatShieldStatus.text = if (threatShieldEnabled) "Active • $threatsBlocked threats blocked" else "Paused"
        updateThreatPullbackUi()

        val isConnected = GhostVpnService.isVpnActive(this)
        if (isConnected) {
            val fp = GhostVpnService.getFingerprint()
            if (fp.isNotEmpty()) txtFingerprint.text = fp

            val peers = GhostVpnService.getPeersCount()
            txtPeersHeader.text = "Linked Devices ($peers)"

            val activeExit = GhostVpnService.getActiveExitNode()
            val pathStr = GhostVpnService.getConnectionPath()
            if (activeExit == "Ad-Shield") {
                txtExitValue.text = "Ad-Shield"
                txtExitSub.text = "Local DNS • $adsBlocked blocked"
                txtConnPath.text = "Local Ad-Shield DNS"
            } else if (activeExit.isNotEmpty() && activeExit != "auto") {
                txtExitValue.text = activeExit
                txtExitSub.text = pathStr
                txtConnPath.text = pathStr
            } else {
                txtExitValue.text = "Auto Mesh"
                txtExitSub.text = pathStr
                txtConnPath.text = pathStr
            }

            val rtt = GhostVpnService.getRttMs()
            val rttStr = if (rtt >= 0) "$rtt ms" else "— ms"
            txtRttValue.text = modes[currentModeIndex]
            txtRttSub.text = if (activeExit == "Ad-Shield") "Ad-Shield • Direct" else "Encrypted • $rttStr"

            txtDnsServer.text = GhostVpnService.activeDnsDisplay
            txtHandovers.text = GhostVpnService.getHandoverCount().toString()

            val stats = GhostVpnService.getStats()
            val rxPkts = if (stats.isNotEmpty()) stats[0] else 0L
            val txPkts = if (stats.size > 1) stats[1] else 0L
            val currentRxBytes = if (stats.size > 4 && stats[4] > 0) stats[4] else rxPkts * 576L
            val currentTxBytes = if (stats.size > 5 && stats[5] > 0) stats[5] else txPkts * 576L

            val rxRate = if (lastTimestamp > 0 && lastRxBytes >= 0 && dt > 0.05) {
                if (currentRxBytes >= lastRxBytes) (currentRxBytes - lastRxBytes) / dt else 0.0
            } else 0.0
            val txRate = if (lastTimestamp > 0 && lastTxBytes >= 0 && dt > 0.05) {
                if (currentTxBytes >= lastTxBytes) (currentTxBytes - lastTxBytes) / dt else 0.0
            } else 0.0

            lastRxBytes = currentRxBytes
            lastTxBytes = currentTxBytes
            lastTimestamp = now

            txtDownSpeed.text = formatRate(rxRate)
            txtDownTotal.text = "${formatBytes(currentRxBytes)} • $rxPkts pkts"
            txtUpSpeed.text = formatRate(txRate)
            txtUpTotal.text = "${formatBytes(currentTxBytes)} • $txPkts pkts"

            peerListContainer.removeAllViews()
            val discovered = GhostVpnService.getDiscoveredPeers()
            if (discovered.isEmpty() && peers > 0) {
                peerListContainer.addView(createPeerRow(activeExit.ifEmpty { "Linked Mesh Exit" }, true))
            } else if (discovered.isEmpty()) {
                peerListContainer.addView(TextView(this).apply {
                    text = "Listening for mesh peers..."
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
                txtExitValue.text = configured
                txtExitSub.text = "Configured Exit"
            } else {
                txtExitValue.text = "Auto Mesh"
                txtExitSub.text = "Standby"
            }
            txtRttValue.text = modes[currentModeIndex]
            txtRttSub.text = "Direct • — ms"
            txtConnPath.text = "Standby"
            txtHandovers.text = "0"
            txtDownSpeed.text = "0 B/s"
            txtUpSpeed.text = "0 B/s"
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

    private fun formatRate(bytesPerSec: Double): String {
        return when {
            bytesPerSec >= 1_048_576.0 -> String.format(Locale.US, "%.1f MB/s", bytesPerSec / 1_048_576.0)
            bytesPerSec >= 1024.0 -> String.format(Locale.US, "%.1f KB/s", bytesPerSec / 1024.0)
            else -> String.format(Locale.US, "%.0f B/s", bytesPerSec)
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1_048_576 -> String.format(Locale.US, "%.1f MB", bytes / 1_048_576.0)
            bytes >= 1024 -> String.format(Locale.US, "%.1f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
    }

    private fun showExitPickerDialog() {
        val discovered = GhostVpnService.getDiscoveredPeers()
        val options = mutableListOf("Auto Mesh (Adaptive)")
        options.addAll(discovered)
        if (discovered.isEmpty()) {
            options.add("Scan Wi-Fi for Devices...")
        }
        android.app.AlertDialog.Builder(this)
            .setTitle("Choose Exit Gateway")
            .setItems(options.toTypedArray()) { _, which ->
                val choice = options[which]
                when {
                    which == 0 -> {
                        editRemoteAddr.setText("")
                        if (GhostVpnService.isRunning) {
                            GhostVpnService.selectExitNode("auto") { _ ->
                                handler.post { updateStatus() }
                            }
                        }
                        Toast.makeText(this, "Exit Gateway: Auto Mesh", Toast.LENGTH_SHORT).show()
                    }
                    choice.startsWith("Scan Wi-Fi") -> {
                        if (GhostVpnService.isRunning) {
                            GhostVpnService.triggerScan { count ->
                                handler.post {
                                    updateStatus()
                                    Toast.makeText(this, "Found $count device(s)", Toast.LENGTH_SHORT).show()
                                }
                            }
                        } else {
                            Toast.makeText(this, "Tap the center button to connect first", Toast.LENGTH_SHORT).show()
                        }
                    }
                    else -> {
                        if (GhostVpnService.isRunning) {
                            GhostVpnService.selectExitNode(choice) { ok ->
                                handler.post {
                                    Toast.makeText(
                                        this,
                                        if (ok) "Routing through $choice" else "Could not switch exit",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                    updateStatus()
                                }
                            }
                        } else {
                            editRemoteAddr.setText(choice)
                            updateStatus()
                        }
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
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
                setTypeface(Typeface.MONOSPACE)
                setTextColor(Color.parseColor("#F4F1EA"))
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })

            addView(TextView(context).apply {
                text = if (isExit) "Active Exit" else "Use as Exit"
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
            centerLedView.background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(Color.parseColor("#F4F1EA"))
            }
            centerLedView.elevation = dp(6).toFloat()
        } else {
            txtCenterState.text = "OFF"
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
                pendingInvite?.let { putExtra(GhostVpnService.EXTRA_INVITE, it) }
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

    private fun modeDescription(mode: String): String = when (mode) {
        "Fast" -> "Fast regime · Direct PQ tunnel, lowest latency"
        "Stealth" -> "Shielded/Ghost · 576B frames + cover shaping"
        "Multi-Hop" -> "Vantablack · 3-hop onion + full shaping"
        else -> "Direct PQ tunnel"
    }

    private fun renderVantablackQrBitmap(uri: String, sizePx: Int): android.graphics.Bitmap {
        val qr = com.google.zxing.qrcode.encoder.Encoder.encode(
            uri,
            com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.H
        )
        val matrix = qr.matrix
        val n = matrix.width
        val quiet = 4
        val total = n + quiet * 2
        val cell = sizePx.toFloat() / total.toFloat()

        val bmp = android.graphics.Bitmap.createBitmap(
            sizePx,
            sizePx,
            android.graphics.Bitmap.Config.ARGB_8888
        )
        val canvas = android.graphics.Canvas(bmp)
        val ivory = Color.parseColor("#EAE6DC")
        val coal = Color.parseColor("#0C0D0F")
        val ghostWhite = Color.parseColor("#F4F1EA")
        val visorNeon = Color.parseColor("#DCFF02")

        // Rounded warm-ivory QR card background
        val bgPaint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = ivory
            style = android.graphics.Paint.Style.FILL
        }
        val cornerR = sizePx * 0.08f
        canvas.drawRoundRect(
            android.graphics.RectF(0f, 0f, sizePx.toFloat(), sizePx.toFloat()),
            cornerR,
            cornerR,
            bgPaint
        )

        val mid = n / 2
        val badgeHalf = if (n >= 45) 4 else if (n >= 29) 3 else 2
        fun inFinder(r: Int, c: Int): Boolean =
            (r < 7 && c < 7) || (r < 7 && c >= n - 7) || (r >= n - 7 && c < 7)
        fun inBadge(r: Int, c: Int): Boolean =
            r in (mid - badgeHalf)..(mid + badgeHalf) && c in (mid - badgeHalf)..(mid + badgeHalf)

        // Connected Liquid Tracks (merged horizontal pill bars)
        val darkPaint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = coal
            style = android.graphics.Paint.Style.FILL
        }
        for (r in 0 until n) {
            var c = 0
            while (c < n) {
                if (matrix.get(c, r).toInt() != 1 || inFinder(r, c) || inBadge(r, c)) {
                    c++
                    continue
                }
                var end = c
                while (end + 1 < n &&
                    matrix.get(end + 1, r).toInt() == 1 &&
                    !inFinder(r, end + 1) &&
                    !inBadge(r, end + 1)
                ) {
                    end++
                }
                val x = (c + quiet + 0.08f) * cell
                val y = (r + quiet + 0.12f) * cell
                val w = ((end - c + 1) - 0.16f) * cell
                val h = 0.76f * cell
                val rx = 0.38f * cell
                canvas.drawRoundRect(android.graphics.RectF(x, y, x + w, y + h), rx, rx, darkPaint)
                c = end + 1
            }
        }

        // Circular Vantablack Finder Eyes
        val ringPaint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = coal
            style = android.graphics.Paint.Style.STROKE
            strokeWidth = 0.95f * cell
        }
        fun drawFinderEye(ox: Int, oy: Int) {
            val cx = (ox + quiet + 3.5f) * cell
            val cy = (oy + quiet + 3.5f) * cell
            canvas.drawCircle(cx, cy, 3.05f * cell, ringPaint)
            canvas.drawCircle(cx, cy, 1.52f * cell, darkPaint)
        }
        drawFinderEye(0, 0)
        drawFinderEye(n - 7, 0)
        drawFinderEye(0, n - 7)

        // Centered Stealth-Visor Ghost Emblem
        val badgeModules = badgeHalf * 2 + 1 + 0.3f
        val bx = (mid - badgeHalf + quiet - 0.15f) * cell
        val by = (mid - badgeHalf + quiet - 0.15f) * cell
        val scale = (badgeModules * cell) / 8.7f

        canvas.save()
        canvas.translate(bx, by)
        canvas.scale(scale, scale)

        // Badge tile + ivory outline
        val tileRect = android.graphics.RectF(0f, 0f, 8.7f, 8.7f)
        canvas.drawRoundRect(tileRect, 2.5f, 2.5f, darkPaint)
        val tileStroke = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = ivory
            style = android.graphics.Paint.Style.STROKE
            strokeWidth = 0.45f
        }
        canvas.drawRoundRect(tileRect, 2.5f, 2.5f, tileStroke)

        // Ghost silhouette path
        val ghostPath = android.graphics.Path().apply {
            moveTo(2.1f, 4.3f)
            cubicTo(2.1f, 1.8f, 6.6f, 1.8f, 6.6f, 4.3f)
            lineTo(6.7f, 6.6f)
            cubicTo(6.2f, 6.1f, 5.7f, 6.65f, 5.15f, 6.65f)
            cubicTo(4.65f, 6.65f, 4.35f, 6.15f, 4.35f, 6.15f)
            cubicTo(4.35f, 6.15f, 4.05f, 6.65f, 3.55f, 6.65f)
            cubicTo(3.0f, 6.65f, 2.5f, 6.1f, 2.0f, 6.6f)
            close()
        }
        val ghostPaint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = ghostWhite
            style = android.graphics.Paint.Style.FILL
        }
        canvas.drawPath(ghostPath, ghostPaint)

        // Visor slot
        canvas.drawRoundRect(android.graphics.RectF(2.65f, 3.45f, 6.05f, 4.70f), 0.62f, 0.62f, darkPaint)

        // Neon visor bar + eye dot
        val visorPaint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = visorNeon
            style = android.graphics.Paint.Style.STROKE
            strokeWidth = 0.32f
            strokeCap = android.graphics.Paint.Cap.ROUND
        }
        canvas.drawLine(3.1f, 3.85f, 4.15f, 3.85f, visorPaint)
        val dotPaint = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = visorNeon
            style = android.graphics.Paint.Style.FILL
        }
        canvas.drawCircle(5.25f, 3.85f, 0.18f, dotPaint)
        canvas.restore()

        return bmp
    }

    private fun showInviteQrDialog() {
        val uri = GhostVpnService.exportInviteUri()
        if (uri.isNullOrEmpty()) {
            Toast.makeText(this, "Tap the center button to connect first", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val size = dp(248)
            val bmp = renderVantablackQrBitmap(uri, size)
            val wrap = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER_HORIZONTAL
                setPadding(dp(22), dp(22), dp(22), dp(18))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#141518"))
                    cornerRadius = dp(20).toFloat()
                    setStroke(dp(1), Color.parseColor("#1FFFFFFF"))
                }
            }
            wrap.addView(TextView(this).apply {
                text = "Invite via QR Code"
                textSize = 16f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, 0, 0, dp(14))
            })
            wrap.addView(ImageView(this).apply {
                setImageBitmap(bmp)
                layoutParams = LinearLayout.LayoutParams(size, size)
            })
            wrap.addView(TextView(this).apply {
                text = "Scan with another Vantablack phone or PC"
                textSize = 12.5f
                setTextColor(Color.parseColor("#99F4F1EA"))
                setPadding(0, dp(14), 0, dp(16))
            })
            val dlg = android.app.AlertDialog.Builder(this)
                .setView(wrap)
                .create()
            dlg.window?.setBackgroundDrawable(android.graphics.drawable.ColorDrawable(Color.TRANSPARENT))

            val btnRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER
            }
            val btnCopy = TextView(this).apply {
                text = "Copy Link"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(dp(18), dp(10), dp(18), dp(10))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#14FFFFFF"))
                    cornerRadius = dp(999).toFloat()
                    setStroke(dp(1), Color.parseColor("#24FFFFFF"))
                }
                setOnClickListener {
                    val clip = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clip.setPrimaryClip(ClipData.newPlainText("Vantablack Invite", uri))
                    Toast.makeText(this@MainActivity, "Invite link copied", Toast.LENGTH_SHORT).show()
                }
            }
            val btnDone = TextView(this).apply {
                text = "Done"
                textSize = 13f
                setTypeface(Typeface.DEFAULT_BOLD)
                setTextColor(Color.parseColor("#0C0D0F"))
                setPadding(dp(22), dp(10), dp(22), dp(10))
                background = GradientDrawable().apply {
                    setColor(Color.parseColor("#F4F1EA"))
                    cornerRadius = dp(999).toFloat()
                }
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { setMargins(dp(10), 0, 0, 0) }
                setOnClickListener { dlg.dismiss() }
            }
            btnRow.addView(btnCopy)
            btnRow.addView(btnDone)
            wrap.addView(btnRow)
            dlg.show()
        } catch (e: Throwable) {
            Toast.makeText(this, "QR error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    // ── QR Scanner & Invite Handling ──
    private fun launchQrScanner() {
        try {
            com.google.zxing.integration.android.IntentIntegrator(this)
                .setCaptureActivity(PortraitCaptureActivity::class.java)
                .setDesiredBarcodeFormats(com.google.zxing.integration.android.IntentIntegrator.QR_CODE)
                .setPrompt("Scan Vantablack QR Code")
                .setBeepEnabled(false)
                .setOrientationLocked(true)
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

    // ── In-App Software Updater ──
    private var availableUpdateUrl: String? = null
    private var availableUpdateVer: String? = null
    private var readyUpdateFile: java.io.File? = null
    private var isDownloadingUpdate = false

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
        val ready = readyUpdateFile
        if (ready != null && ready.exists() && ready.length() >= 50_000L) {
            installApk(ready)
            return
        }
        val url = availableUpdateUrl
        val ver = availableUpdateVer
        if (!url.isNullOrEmpty() && !ver.isNullOrEmpty()) {
            downloadApkInBackground(url, "vantablack-${ver.trimStart('v')}-android.apk", ver)
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
                    val htmlUrl = json.optString("html_url", "https://github.com/KELLERBABG/Vantablack/releases/latest")
                    val newerTag = tag.isNotEmpty() && isNewerVersion(tag, currentVer)
                    val hasApkUpdate = newerTag && !apkUrl.isNullOrEmpty()
                    handler.post {
                        if (hasApkUpdate && apkUrl != null) {
                            availableUpdateUrl = apkUrl
                            availableUpdateVer = tag
                            val fileName = "vantablack-${tag.trimStart('v')}-android.apk"
                            val targetDir = getExternalFilesDir(android.os.Environment.DIRECTORY_DOWNLOADS) ?: cacheDir
                            val cached = java.io.File(targetDir, fileName)
                            if (cached.exists() && cached.length() >= 50_000L) {
                                readyUpdateFile = cached
                                btnUpdateBadge.visibility = View.VISIBLE
                                btnUpdateBadge.text = "⚡ Install $tag"
                                txtUpdateStatus.text = "Vantablack $tag downloaded — tap Install when ready"
                                btnUpdateAction.text = "Install $tag"
                            } else {
                                btnUpdateBadge.visibility = View.VISIBLE
                                btnUpdateBadge.text = "⚡ Update $tag"
                                txtUpdateStatus.text = "New version $tag found — downloading in background..."
                                btnUpdateAction.text = "Downloading..."
                                downloadApkInBackground(apkUrl, fileName, tag)
                            }
                            btnUpdateAction.setTextColor(Color.parseColor("#0C0D0F"))
                            btnUpdateAction.background = GradientDrawable().apply {
                                setColor(Color.parseColor("#F4F1EA"))
                                cornerRadius = dp(999).toFloat()
                            }
                        } else if (newerTag) {
                            availableUpdateUrl = null
                            availableUpdateVer = null
                            btnUpdateBadge.visibility = View.VISIBLE
                            btnUpdateBadge.text = "⚡ Update $tag"
                            txtUpdateStatus.text = "Vantablack $tag released (open page)"
                            btnUpdateAction.text = "Open"
                            if (userInitiated) {
                                Toast.makeText(this, "Release $tag found — opening release page", Toast.LENGTH_SHORT).show()
                                try {
                                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(htmlUrl)))
                                } catch (_: Throwable) {}
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

    private fun downloadApkInBackground(downloadUrl: String, fileName: String, tag: String) {
        if (isDownloadingUpdate) return
        isDownloadingUpdate = true
        txtUpdateStatus.text = "Downloading $tag in background..."
        btnUpdateAction.text = "0%"

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
                var lastPct = -1
                while (input.read(buffer).also { count = it } != -1) {
                    total += count
                    if (fileLength > 0) {
                        val progress = ((total * 100) / fileLength).toInt()
                        if (progress != lastPct) {
                            lastPct = progress
                            handler.post {
                                txtUpdateStatus.text = "Downloading $tag... $progress%"
                                btnUpdateAction.text = "$progress%"
                            }
                        }
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
                    isDownloadingUpdate = false
                    readyUpdateFile = targetFile
                    btnUpdateBadge.visibility = View.VISIBLE
                    btnUpdateBadge.text = "⚡ Install $tag"
                    txtUpdateStatus.text = "Vantablack $tag downloaded — tap Install when ready"
                    btnUpdateAction.text = "Install $tag"
                    Toast.makeText(this, "Vantablack $tag ready to install", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Throwable) {
                handler.post {
                    isDownloadingUpdate = false
                    txtUpdateStatus.text = "Download failed (${e.message})"
                    btnUpdateAction.text = "Retry"
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
