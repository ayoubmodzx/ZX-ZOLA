package com.zx.zola

import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.IBinder
import android.view.*
import android.view.animation.DecelerateInterpolator
import android.widget.*
import androidx.core.content.ContextCompat

class ZxOverlayService : Service() {

    // ── Data ────────────────────────────────────────────────────────────────
    enum class Risk { SAFE, RISK, DANGER }

    data class Feature(
        val name: String,
        val cmd: Int,
        val risk: Risk,
        val hasSlider: Boolean = false,
        val sliderMin: Int = 0,
        val sliderMax: Int = 100,
        val sliderDefault: Int = 50,
        val sliderLabel: String = ""
    )

    enum class Tab(val label: String, val icon: String) {
        AIM("AIM", "◎"),
        WEAPON("WEAPON", "⊕"),
        MOVEMENT("MOVE", "⇨"),
        SURVIVAL("SURVIVE", "♥"),
        VISUAL("VISUAL", "◉")
    }

    private val featureMap: Map<Tab, List<Feature>> = mapOf(
        Tab.AIM to listOf(
            Feature("Aim Assist",    ZxEngine.Cmd.AIM_ENABLE,    Risk.RISK),
            Feature("Auto Headshot", ZxEngine.Cmd.AUTO_HEADSHOT, Risk.RISK),
            Feature("Silent Aim",    ZxEngine.Cmd.SILENT_AIM,    Risk.DANGER),
            Feature("Full Aimbot",   ZxEngine.Cmd.FULL_AIMBOT,   Risk.DANGER),
            Feature("Anti-Aim",      ZxEngine.Cmd.ANTI_AIM,      Risk.DANGER),
            Feature("Aim FOV",       ZxEngine.Cmd.AIM_FOV,       Risk.RISK,
                hasSlider=true, sliderMin=5, sliderMax=90, sliderDefault=30, sliderLabel="°"),
            Feature("Smoothness",    ZxEngine.Cmd.AIM_SMOOTH,    Risk.RISK,
                hasSlider=true, sliderDefault=40, sliderLabel="%")
        ),
        Tab.WEAPON to listOf(
            Feature("Anti Recoil",   ZxEngine.Cmd.ANTI_RECOIL,   Risk.SAFE),
            Feature("No Spread",     ZxEngine.Cmd.NO_SPREAD,      Risk.SAFE),
            Feature("Rapid Fire",    ZxEngine.Cmd.RAPID_FIRE,     Risk.RISK),
            Feature("Rapid Fire+",   ZxEngine.Cmd.RAPID_FIRE_RISK,Risk.DANGER),
            Feature("Infinite Ammo", ZxEngine.Cmd.INFINITE_AMMO,  Risk.DANGER),
            Feature("No Reload",     ZxEngine.Cmd.NO_RELOAD,      Risk.DANGER),
            Feature("Wall Shoot",    ZxEngine.Cmd.WALL_SHOOT,     Risk.DANGER)
        ),
        Tab.MOVEMENT to listOf(
            Feature("Vehicle Speed", ZxEngine.Cmd.VEHICLE_SPEED,  Risk.SAFE,
                hasSlider=true, sliderMin=10, sliderMax=200, sliderDefault=50, sliderLabel="%"),
            Feature("Speed Hack",    ZxEngine.Cmd.SPEED_HACK,     Risk.RISK,
                hasSlider=true, sliderMin=10, sliderMax=200, sliderDefault=40, sliderLabel="%"),
            Feature("High Jump",     ZxEngine.Cmd.HIGH_JUMP,      Risk.RISK,
                hasSlider=true, sliderMin=10, sliderMax=200, sliderDefault=50, sliderLabel="%"),
            Feature("No-Clip",       ZxEngine.Cmd.NOCLIP,         Risk.DANGER),
            Feature("Teleport",      ZxEngine.Cmd.TELEPORT,       Risk.DANGER)
        ),
        Tab.SURVIVAL to listOf(
            Feature("Anti Damage",   ZxEngine.Cmd.ANTI_DAMAGE,    Risk.RISK,
                hasSlider=true, sliderMin=0, sliderMax=100, sliderDefault=50, sliderLabel="%"),
            Feature("Auto Revive",   ZxEngine.Cmd.AUTO_REVIVE,    Risk.RISK),
            Feature("God Mode",      ZxEngine.Cmd.GOD_MODE,       Risk.DANGER)
        ),
        Tab.VISUAL to listOf(
            Feature("ESP",           ZxEngine.Cmd.ESP,            Risk.SAFE),
            Feature("Wide FOV",      ZxEngine.Cmd.WIDE_POV,       Risk.SAFE,
                hasSlider=true, sliderMin=60, sliderMax=150, sliderDefault=90, sliderLabel="°"),
            Feature("No Grass",      ZxEngine.Cmd.NO_GRASS,       Risk.SAFE)
        )
    )

    // ── State ────────────────────────────────────────────────────────────────
    private lateinit var windowManager: WindowManager
    private lateinit var rootView: View
    private var currentTab = Tab.AIM
    private val switchMap = mutableMapOf<Int, Switch>()
    private val tabViews = mutableMapOf<Tab, View>()
    private lateinit var contentScroll: ScrollView
    private lateinit var contentList: LinearLayout
    private var isConnected = false
    private lateinit var statusDot: View
    private lateinit var statusText: TextView

    // drag state
    private var dragX = 0f; private var dragY = 0f
    private var winX = 20; private var winY = 150

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager
        buildOverlay()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (::rootView.isInitialized) windowManager.removeView(rootView)
    }

    // ── Build ─────────────────────────────────────────────────────────────────
    private fun buildOverlay() {
        val params = WindowManager.LayoutParams(
            dpToPx(380), WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).also { it.gravity = Gravity.TOP or Gravity.START; it.x = winX; it.y = winY }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_overlay_root)
            elevation = 16f
        }

        root.addView(buildHeader())
        root.addView(buildDividerH())

        val body = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        body.addView(buildSidebar())
        body.addView(buildDividerV())
        body.addView(buildContent())
        root.addView(body)

        rootView = root
        windowManager.addView(root, params)

        // drag on header
        root.getChildAt(0).setOnTouchListener { _, ev -> handleDrag(ev, params); true }

        selectTab(Tab.AIM)
    }

    // ── Header ────────────────────────────────────────────────────────────────
    private fun buildHeader(): View {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dpToPx(14), dpToPx(10), dpToPx(14), dpToPx(10))
            background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_header)

            // Logo + name
            addView(TextView(this@ZxOverlayService).apply {
                text = "ZX"
                setTextColor(Color.parseColor("#7C4DFF"))
                textSize = 16f
                typeface = android.graphics.Typeface.DEFAULT_BOLD
                setPadding(0,0,dpToPx(4),0)
            })
            addView(TextView(this@ZxOverlayService).apply {
                text = "ZOLA"
                setTextColor(Color.WHITE)
                textSize = 16f
                typeface = android.graphics.Typeface.DEFAULT_BOLD
            })
            addView(View(this@ZxOverlayService).apply {
                layoutParams = LinearLayout.LayoutParams(0, 0, 1f)
            })

            // Status indicator
            statusDot = View(this@ZxOverlayService).apply {
                layoutParams = LinearLayout.LayoutParams(dpToPx(8), dpToPx(8)).also {
                    it.gravity = Gravity.CENTER_VERTICAL
                    it.marginEnd = dpToPx(6)
                }
                background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_status_dot_off)
            }
            addView(statusDot)
            statusText = TextView(this@ZxOverlayService).apply {
                text = "OFFLINE"
                setTextColor(Color.parseColor("#9090B0"))
                textSize = 10f
                setPadding(0,0,dpToPx(10),0)
            }
            addView(statusText)

            // Close
            addView(TextView(this@ZxOverlayService).apply {
                text = "✕"
                setTextColor(Color.parseColor("#9090B0"))
                textSize = 14f
                setOnClickListener { stopSelf() }
            })
        }
    }

    // ── Sidebar ───────────────────────────────────────────────────────────────
    private fun buildSidebar(): View {
        val sidebar = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(dpToPx(72), LinearLayout.LayoutParams.WRAP_CONTENT)
            background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_sidebar)
            setPadding(0, dpToPx(8), 0, dpToPx(8))
        }
        Tab.values().forEach { tab ->
            val tv = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                setPadding(dpToPx(6), dpToPx(10), dpToPx(6), dpToPx(10))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            }
            tv.addView(TextView(this).apply {
                text = tab.icon
                setTextColor(Color.parseColor("#9090B0"))
                textSize = 18f
                gravity = Gravity.CENTER
            })
            tv.addView(TextView(this).apply {
                text = tab.label
                setTextColor(Color.parseColor("#9090B0"))
                textSize = 8f
                gravity = Gravity.CENTER
                letterSpacing = 0.1f
            })
            tv.setOnClickListener { selectTab(tab) }
            tabViews[tab] = tv
            sidebar.addView(tv)
        }
        return sidebar
    }

    // ── Content ───────────────────────────────────────────────────────────────
    private fun buildContent(): View {
        contentScroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            isVerticalScrollBarEnabled = false
        }
        contentList = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(10), dpToPx(8), dpToPx(10), dpToPx(8))
        }
        contentScroll.addView(contentList)
        return contentScroll
    }

    private fun selectTab(tab: Tab) {
        currentTab = tab
        // Update sidebar visual
        tabViews.forEach { (t, v) ->
            val isSelected = t == tab
            v.background = ContextCompat.getDrawable(this,
                if (isSelected) R.drawable.bg_tab_selected else R.drawable.bg_tab_normal)
            val color = if (isSelected) Color.WHITE else Color.parseColor("#9090B0")
            val accentColor = if (isSelected) Color.parseColor("#7C4DFF") else Color.parseColor("#9090B0")
            (v as LinearLayout).let { ll ->
                (ll.getChildAt(0) as TextView).setTextColor(accentColor)
                (ll.getChildAt(1) as TextView).setTextColor(color)
            }
        }
        // Rebuild content
        contentList.removeAllViews()
        val features = featureMap[tab] ?: return

        // Group by risk
        val safeFeatures   = features.filter { it.risk == Risk.SAFE }
        val riskFeatures   = features.filter { it.risk == Risk.RISK }
        val dangerFeatures = features.filter { it.risk == Risk.DANGER }

        if (safeFeatures.isNotEmpty()) {
            addSectionHeader("SAFE", "#00E676")
            safeFeatures.forEach { addFeatureRow(it) }
        }
        if (riskFeatures.isNotEmpty()) {
            if (safeFeatures.isNotEmpty()) contentList.addView(buildDividerH())
            addSectionHeader("RISK", "#FFD740")
            riskFeatures.forEach { addFeatureRow(it) }
        }
        if (dangerFeatures.isNotEmpty()) {
            if (safeFeatures.isNotEmpty() || riskFeatures.isNotEmpty()) contentList.addView(buildDividerH())
            addSectionHeader("DANGER", "#FF1744")
            dangerFeatures.forEach { addFeatureRow(it) }
        }
    }

    private fun addSectionHeader(label: String, colorHex: String) {
        contentList.addView(TextView(this).apply {
            text = "▸  $label"
            setTextColor(Color.parseColor(colorHex))
            textSize = 9f
            letterSpacing = 0.2f
            setPadding(dpToPx(4), dpToPx(6), 0, dpToPx(4))
        })
    }

    private fun addFeatureRow(feature: Feature) {
        val bgRes = when(feature.risk) {
            Risk.SAFE   -> R.drawable.bg_feature_safe
            Risk.RISK   -> R.drawable.bg_feature_risk
            Risk.DANGER -> R.drawable.bg_feature_danger
        }
        val badgeRes = when(feature.risk) {
            Risk.SAFE   -> R.drawable.bg_badge_safe
            Risk.RISK   -> R.drawable.bg_badge_risk
            Risk.DANGER -> R.drawable.bg_badge_danger
        }
        val badgeColor = when(feature.risk) {
            Risk.SAFE   -> "#00E676"
            Risk.RISK   -> "#FFD740"
            Risk.DANGER -> "#FF1744"
        }
        val badgeText = when(feature.risk) {
            Risk.SAFE   -> "SAFE"
            Risk.RISK   -> "RISK"
            Risk.DANGER -> "HOT"
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ContextCompat.getDrawable(this@ZxOverlayService, bgRes)
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            lp.setMargins(0, 0, 0, dpToPx(4))
            layoutParams = lp
            setPadding(dpToPx(10), dpToPx(8), dpToPx(10), dpToPx(8))
        }

        // Row: name + badge + switch
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        row.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)

            addView(TextView(this@ZxOverlayService).apply {
                text = feature.name
                setTextColor(Color.WHITE)
                textSize = 12f
            })

            // Badge
            addView(TextView(this@ZxOverlayService).apply {
                text = badgeText
                setTextColor(Color.parseColor(badgeColor))
                textSize = 8f
                background = ContextCompat.getDrawable(this@ZxOverlayService, badgeRes)
                val lp2 = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
                lp2.topMargin = dpToPx(2)
                layoutParams = lp2
                setPadding(dpToPx(5), dpToPx(2), dpToPx(5), dpToPx(2))
            })
        })

        val sw = Switch(this).apply {
            isChecked = false
            trackDrawable = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.sel_switch_track)
            thumbDrawable = null
            setOnCheckedChangeListener { _, on ->
                ZxEngine.toggle(feature.cmd, on)
            }
        }
        switchMap[feature.cmd] = sw
        row.addView(sw)
        card.addView(row)

        // Slider if needed
        if (feature.hasSlider) {
            val sliderRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                val lp = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                lp.topMargin = dpToPx(6)
                layoutParams = lp
            }
            val valLabel = TextView(this).apply {
                text = "${feature.sliderDefault}${feature.sliderLabel}"
                setTextColor(Color.parseColor("#7C4DFF"))
                textSize = 10f
                minWidth = dpToPx(36)
            }
            val seek = SeekBar(this).apply {
                max = feature.sliderMax - feature.sliderMin
                progress = feature.sliderDefault - feature.sliderMin
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                progressDrawable = null
                thumb = null
                // Simple styling
                setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                    override fun onProgressChanged(sb: SeekBar, p: Int, fromUser: Boolean) {
                        val actual = p + feature.sliderMin
                        valLabel.text = "$actual${feature.sliderLabel}"
                        if (fromUser) ZxEngine.setIntensity(feature.cmd, p * 100 / (feature.sliderMax - feature.sliderMin))
                    }
                    override fun onStartTrackingTouch(sb: SeekBar) {}
                    override fun onStopTrackingTouch(sb: SeekBar) {}
                })
            }
            sliderRow.addView(seek)
            sliderRow.addView(valLabel)
            card.addView(sliderRow)
        }

        contentList.addView(card)
    }

    // ── Dividers ──────────────────────────────────────────────────────────────
    private fun buildDividerH() = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dpToPx(1))
        setBackgroundColor(Color.parseColor("#1E1E3A"))
    }

    private fun buildDividerV() = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(dpToPx(1), LinearLayout.LayoutParams.MATCH_PARENT)
        setBackgroundColor(Color.parseColor("#1E1E3A"))
    }

    // ── Drag ──────────────────────────────────────────────────────────────────
    private fun handleDrag(ev: MotionEvent, params: WindowManager.LayoutParams) {
        when (ev.action) {
            MotionEvent.ACTION_DOWN -> { dragX = ev.rawX; dragY = ev.rawY }
            MotionEvent.ACTION_MOVE -> {
                params.x += (ev.rawX - dragX).toInt()
                params.y += (ev.rawY - dragY).toInt()
                dragX = ev.rawX; dragY = ev.rawY
                windowManager.updateViewLayout(rootView, params)
            }
        }
    }

    // ── Status ─────────────────────────────────────────────────────────────────
    fun setConnected(pid: Int) {
        isConnected = true
        statusDot.post {
            statusDot.background = ContextCompat.getDrawable(this, R.drawable.bg_status_dot_on)
            statusText.text = "PID $pid"
            statusText.setTextColor(Color.parseColor("#00E676"))
        }
    }

    // ── Util ──────────────────────────────────────────────────────────────────
    private fun dpToPx(dp: Int) = (dp * resources.displayMetrics.density).toInt()
}
