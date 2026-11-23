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

        // Real Flanks Row: Exit Gateway (left) & Latency / Tunnel State (right)
        val flanksRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            weightSum = 2f
            setPadding(dp(6), dp(22), dp(6), 0)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }

        val leftFlank = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.START
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1.15f)
            addView(TextView(context).apply {
                text = "EXIT GATEWAY"
                textSize = 10f
                letterSpacing = 0.14f
                setTextColor(Color.parseColor("#787774"))
            })
            txtExitValue = TextView(context).apply {
                text = "Auto Mesh"
                textSize = 17f
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                setTypeface(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, dp(2), 0, 0)
            }
            addView(txtExitValue)
            txtExitSub = TextView(context).apply {
                text = "Standby"
                textSize = 12f
                setTextColor(Color.parseColor("#9E9C98"))
            }
            addView(txtExitSub)
        }

        val rightFlank = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.END
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.85f)
            addView(TextView(context).apply {
                text = "LATENCY"
                textSize = 10f
                letterSpacing = 0.14f
                gravity = Gravity.END
                setTextColor(Color.parseColor("#787774"))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            })
            txtRttValue = TextView(context).apply {
                text = "— ms"
                textSize = 17f
                gravity = Gravity.END
                setTypeface(Typeface.DEFAULT, Typeface.BOLD)
                setTextColor(Color.parseColor("#F4F1EA"))
                setPadding(0, dp(2), 0, 0)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            addView(txtRttValue)
            txtRttSub = TextView(context).apply {
                text = "Direct"
                textSize = 12f
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

        // ── Quick Pairing Pill Dock (+ Scan QR Code & Paste Invite Link) ──
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
            ).apply { setMargins(0, 0, 0, dp(14)) }
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

    private fun updateStatus() {
        val now = System.currentTimeMillis()
        val dt = if (lastTimestamp > 0) ((now - lastTimestamp) / 1000.0).coerceAtLeast(0.1) else 1.0

        val isConnected = GhostVpnService.isVpnActive(this)
        if (isConnected) {
            val fp = GhostVpnService.getFingerprint()
            if (fp.isNotEmpty()) txtFingerprint.text = fp

            val peers = GhostVpnService.getPeersCount()
            txtPeersHeader.text = "Linked Devices ($peers)"

            val activeExit = GhostVpnService.getActiveExitNode()
            val pathStr = GhostVpnService.getConnectionPath()
            if (activeExit.isNotEmpty() && activeExit != "auto") {
                txtExitValue.text = activeExit
                txtExitSub.text = pathStr
            } else {
                txtExitValue.text = "Auto Mesh"
                txtExitSub.text = pathStr
            }

            val rtt = GhostVpnService.getRttMs()
            txtRttValue.text = if (rtt >= 0) "$rtt ms" else "— ms"
            txtRttSub.text = "Encrypted"

            txtConnPath.text = pathStr
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
            txtRttValue.text = "— ms"
            txtRttSub.text = "Direct"
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
