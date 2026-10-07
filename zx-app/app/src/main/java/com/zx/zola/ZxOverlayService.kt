package com.zx.zola

import android.app.Service
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.IBinder
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import kotlin.math.abs

class ZxOverlayService : Service() {

    companion object {
        const val ACTION_TOGGLE_FAB = "com.zx.zola.TOGGLE_FAB"
        private const val FAB_DP    = 56
        private const val MIN_W_DP  = 280
        private const val MIN_H_DP  = 330
        private const val DEF_W_DP  = 370
        private const val DEF_H_DP  = 440
    }

    // ─── Data ─────────────────────────────────────────────────────────────────
    enum class Risk { SAFE, RISK, DANGER }

    data class Feature(
        val name:          String,
        val cmd:           Int,
        val risk:          Risk,
        val hasSlider:     Boolean = false,
        val sliderMin:     Int     = 0,
        val sliderMax:     Int     = 100,
        val sliderDefault: Int     = 50,
        val sliderLabel:   String  = ""
    )

    enum class Tab(val label: String, val icon: String) {
        AIM     ("AIM",     "◎"),
        WEAPON  ("WEAPON",  "⊕"),
        MOVEMENT("MOVE",    "⇨"),
        SURVIVAL("SURVIVE", "♥"),
        VISUAL  ("VISUAL",  "◉")
    }

    private val features: Map<Tab, List<Feature>> = mapOf(
        Tab.AIM to listOf(
            Feature("Auto Headshot",  ZxEngine.Cmd.AUTO_HEADSHOT,  Risk.SAFE),
            Feature("Aim Assist",     ZxEngine.Cmd.AIM_ENABLE,     Risk.RISK),
            Feature("Aim FOV",        ZxEngine.Cmd.AIM_FOV,        Risk.RISK,
                hasSlider = true, sliderMin = 5, sliderMax = 90, sliderDefault = 30, sliderLabel = "°"),
            Feature("Aim Bone",       ZxEngine.Cmd.AIM_BONE,       Risk.RISK,
                hasSlider = true, sliderMin = 0, sliderMax = 2, sliderDefault = 0,  sliderLabel = ""),
            Feature("Smoothness",     ZxEngine.Cmd.AIM_SMOOTH,     Risk.RISK,
                hasSlider = true, sliderDefault = 40, sliderLabel = "%"),
            Feature("Silent Aim",     ZxEngine.Cmd.SILENT_AIM,     Risk.DANGER),
            Feature("Full Aimbot",    ZxEngine.Cmd.FULL_AIMBOT,    Risk.DANGER),
            Feature("Anti-Aim",       ZxEngine.Cmd.ANTI_AIM,       Risk.DANGER)
        ),
        Tab.WEAPON to listOf(
            Feature("Anti Recoil",    ZxEngine.Cmd.ANTI_RECOIL,    Risk.SAFE),
            Feature("No Spread",      ZxEngine.Cmd.NO_SPREAD,       Risk.SAFE),
            Feature("Rapid Fire",     ZxEngine.Cmd.RAPID_FIRE,      Risk.RISK),
            Feature("Rapid Fire+",    ZxEngine.Cmd.RAPID_FIRE_RISK, Risk.DANGER),
            Feature("Infinite Ammo",  ZxEngine.Cmd.INFINITE_AMMO,   Risk.DANGER),
            Feature("No Reload",      ZxEngine.Cmd.NO_RELOAD,        Risk.DANGER),
            Feature("Wall Shoot",     ZxEngine.Cmd.WALL_SHOOT,       Risk.DANGER)
        ),
        Tab.MOVEMENT to listOf(
            Feature("Vehicle Speed",  ZxEngine.Cmd.VEHICLE_SPEED,  Risk.SAFE,
                hasSlider = true, sliderMin = 10, sliderMax = 200, sliderDefault = 50, sliderLabel = "%"),
            Feature("Save Position",  ZxEngine.Cmd.TELEPORT_SAVE,  Risk.SAFE),
            Feature("Speed Hack",     ZxEngine.Cmd.SPEED_HACK,     Risk.RISK,
                hasSlider = true, sliderMin = 10, sliderMax = 200, sliderDefault = 40, sliderLabel = "%"),
            Feature("High Jump",      ZxEngine.Cmd.HIGH_JUMP,      Risk.RISK,
                hasSlider = true, sliderMin = 10, sliderMax = 200, sliderDefault = 50, sliderLabel = "%"),
            Feature("No-Clip",        ZxEngine.Cmd.NOCLIP,         Risk.DANGER),
            Feature("Teleport",       ZxEngine.Cmd.TELEPORT,       Risk.DANGER)
        ),
        Tab.SURVIVAL to listOf(
            Feature("Anti Damage",    ZxEngine.Cmd.ANTI_DAMAGE,    Risk.RISK,
                hasSlider = true, sliderDefault = 50, sliderLabel = "%"),
            Feature("Auto Revive",    ZxEngine.Cmd.AUTO_REVIVE,    Risk.RISK),
            Feature("God Mode",       ZxEngine.Cmd.GOD_MODE,       Risk.DANGER)
        ),
        Tab.VISUAL to listOf(
            Feature("ESP",            ZxEngine.Cmd.ESP,            Risk.SAFE),
            Feature("Wide FOV",       ZxEngine.Cmd.WIDE_POV,       Risk.SAFE,
                hasSlider = true, sliderMin = 60, sliderMax = 150, sliderDefault = 90, sliderLabel = "°"),
            Feature("No Grass",       ZxEngine.Cmd.NO_GRASS,       Risk.SAFE)
        )
    )

    // ─── Window state ─────────────────────────────────────────────────────────
    private lateinit var wm: WindowManager
    private var fabView  : View? = null
    private var panelRoot: View? = null
    private lateinit var fabLp  : WindowManager.LayoutParams
    private lateinit var panelLp: WindowManager.LayoutParams

    private var panelVisible = false
    private var fabVisible   = true
    private var panelW = 0
    private var panelH = 0

    // raw pointer coords for drag / resize
    private var fabRawX = 0f;  private var fabRawY = 0f
    private var pDragX  = 0f;  private var pDragY  = 0f
    private var rStartX = 0f;  private var rStartY = 0f
    private var rStartW = 0;   private var rStartH = 0

    // content refs set during buildPanel
    private lateinit var contentList: LinearLayout
    private lateinit var statusDot  : View
    private lateinit var statusText : TextView
    private var currentTab = Tab.AIM
    private val switchMap  = mutableMapOf<Int, Switch>()
    private val tabViews   = mutableMapOf<Tab, View>()

    // ─── Lifecycle ────────────────────────────────────────────────────────────
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        wm = getSystemService(WINDOW_SERVICE) as WindowManager
        panelW = dp(DEF_W_DP)
        panelH = dp(DEF_H_DP)
        createFab()
        createPanel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_TOGGLE_FAB) toggleFabVisibility()
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        fabView  ?.let { if (it.parent != null) wm.removeView(it) }
        panelRoot?.let { if (it.parent != null) wm.removeView(it) }
    }

    // ─── FAB ──────────────────────────────────────────────────────────────────
    private fun createFab() {
        val sz = dp(FAB_DP)
        fabLp = secureOverlayLp(sz, sz).apply { x = 20; y = 400 }

        val fab = FrameLayout(this).apply {
            background = GradientDrawable().also {
                it.shape = GradientDrawable.OVAL
                it.setColor(Color.parseColor("#7C4DFF"))
                it.setStroke(dp(2), Color.parseColor("#A87DFF"))
            }
            elevation = 24f
        }
        fab.addView(ImageView(this).apply {
            setImageDrawable(ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.ic_zx))
            layoutParams = FrameLayout.LayoutParams(dp(26), dp(26), Gravity.CENTER)
        })

        fabView = fab
        wm.addView(fab, fabLp)
        attachFabTouch(fab)
    }

    private fun attachFabTouch(fab: View) {
        var isTap  = true
        var downMs = 0L
        fab.setOnTouchListener { _, ev ->
            when (ev.action) {
                MotionEvent.ACTION_DOWN -> {
                    fabRawX = ev.rawX; fabRawY = ev.rawY
                    downMs = System.currentTimeMillis(); isTap = true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = ev.rawX - fabRawX; val dy = ev.rawY - fabRawY
                    if (abs(dx) > dp(6) || abs(dy) > dp(6)) isTap = false
                    fabLp.x += dx.toInt(); fabLp.y += dy.toInt()
                    fabRawX = ev.rawX; fabRawY = ev.rawY
                    if (fab.parent != null) wm.updateViewLayout(fab, fabLp)
                }
                MotionEvent.ACTION_UP -> {
                    if (isTap && System.currentTimeMillis() - downMs < 350) togglePanel()
                }
            }
            true
        }
    }

    private fun toggleFabVisibility() {
        fabVisible = !fabVisible
        if (fabVisible) {
            if (fabView?.parent == null) wm.addView(fabView, fabLp)
        } else {
            if (panelVisible) togglePanel()
            fabView?.let { if (it.parent != null) wm.removeView(it) }
        }
    }

    // ─── Panel ────────────────────────────────────────────────────────────────
    private fun createPanel() {
        panelLp = secureOverlayLp(panelW, panelH).apply { x = 40; y = 80 }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_overlay_root)
            elevation = 16f
        }

        val header = buildHeader()
        root.addView(header)
        root.addView(divH())

        val body = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        }
        body.addView(buildSidebar())
        body.addView(divV())
        body.addView(buildContent())
        root.addView(body)
        root.addView(buildResizeHandle())

        panelRoot = root

        // Drag panel by its header; children (close ✕) still consume their own taps
        header.setOnTouchListener { _, ev ->
            when (ev.action) {
                MotionEvent.ACTION_DOWN -> { pDragX = ev.rawX; pDragY = ev.rawY }
                MotionEvent.ACTION_MOVE -> {
                    panelLp.x += (ev.rawX - pDragX).toInt()
                    panelLp.y += (ev.rawY - pDragY).toInt()
                    pDragX = ev.rawX; pDragY = ev.rawY
                    panelRoot?.let { if (it.parent != null) wm.updateViewLayout(it, panelLp) }
                }
            }
            true
        }
        // panel starts hidden — added to WM on first togglePanel()
    }

    private fun togglePanel() {
        if (panelVisible) {
            panelRoot?.let { if (it.parent != null) wm.removeView(it) }
            panelVisible = false
        } else {
            panelRoot?.let { if (it.parent == null) wm.addView(it, panelLp) }
            panelVisible = true
            selectTab(currentTab)
        }
    }

    // ─── Header ───────────────────────────────────────────────────────────────
    private fun buildHeader(): View = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(dp(12), dp(9), dp(12), dp(9))
        background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_header)

        addView(ImageView(this@ZxOverlayService).apply {
            setImageDrawable(ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.ic_zx))
            layoutParams = LinearLayout.LayoutParams(dp(18), dp(18)).also { it.marginEnd = dp(7) }
        })
        addView(TextView(this@ZxOverlayService).apply {
            text = "ZX"
            setTextColor(Color.parseColor("#7C4DFF"))
            textSize = 14f
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        })
        addView(TextView(this@ZxOverlayService).apply {
            text = "  by AYOUB"
            setTextColor(Color.parseColor("#50508A"))
            textSize = 8.5f
        })
        // spacer
        addView(View(this@ZxOverlayService).apply {
            layoutParams = LinearLayout.LayoutParams(0, 1, 1f)
        })

        statusDot = View(this@ZxOverlayService).apply {
            layoutParams = LinearLayout.LayoutParams(dp(7), dp(7)).also {
                it.gravity = Gravity.CENTER_VERTICAL; it.marginEnd = dp(5)
            }
            background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_status_dot_off)
        }
        addView(statusDot)
        statusText = TextView(this@ZxOverlayService).apply {
            text = "OFFLINE"
            setTextColor(Color.parseColor("#9090B0"))
            textSize = 9f
            setPadding(0, 0, dp(8), 0)
        }
        addView(statusText)

        // Close hides panel, does NOT kill service
        addView(TextView(this@ZxOverlayService).apply {
            text = "✕"
            setTextColor(Color.parseColor("#9090B0"))
            textSize = 13f
            setPadding(dp(4), 0, 0, 0)
            setOnClickListener { togglePanel() }
        })
    }

    // ─── Sidebar ──────────────────────────────────────────────────────────────
    private fun buildSidebar(): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        layoutParams = LinearLayout.LayoutParams(dp(68), LinearLayout.LayoutParams.MATCH_PARENT)
        background = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.bg_sidebar)
        setPadding(0, dp(8), 0, dp(8))

        Tab.values().forEach { tab ->
            val item = LinearLayout(this@ZxOverlayService).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                setPadding(dp(6), dp(10), dp(6), dp(10))
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            }
            item.addView(TextView(this@ZxOverlayService).apply {
                text = tab.icon; setTextColor(Color.parseColor("#9090B0"))
                textSize = 17f; gravity = Gravity.CENTER
            })
            item.addView(TextView(this@ZxOverlayService).apply {
                text = tab.label; setTextColor(Color.parseColor("#9090B0"))
                textSize = 7.5f; gravity = Gravity.CENTER; letterSpacing = 0.08f
            })
            item.setOnClickListener { selectTab(tab) }
            tabViews[tab] = item
            addView(item)
        }
    }

    // ─── Content ──────────────────────────────────────────────────────────────
    private fun buildContent(): View {
        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.MATCH_PARENT, 1f)
            isVerticalScrollBarEnabled = false
        }
        contentList = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }
        scroll.addView(contentList)
        return scroll
    }

    // ─── Resize handle ────────────────────────────────────────────────────────
    private fun buildResizeHandle(): View = FrameLayout(this).apply {
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(18))
        setBackgroundColor(Color.parseColor("#0D0D1A"))

        addView(TextView(this@ZxOverlayService).apply {
            text = "⌟"
            setTextColor(Color.parseColor("#4040A0"))
            textSize = 13f; gravity = Gravity.CENTER
            layoutParams = FrameLayout.LayoutParams(dp(24), dp(18), Gravity.END or Gravity.CENTER_VERTICAL)
        })
        setOnTouchListener { _, ev ->
            when (ev.action) {
                MotionEvent.ACTION_DOWN -> {
                    rStartX = ev.rawX; rStartY = ev.rawY
                    rStartW = panelW;  rStartH = panelH
                }
                MotionEvent.ACTION_MOVE -> {
                    panelW = (rStartW + (ev.rawX - rStartX).toInt()).coerceAtLeast(dp(MIN_W_DP))
                    panelH = (rStartH + (ev.rawY - rStartY).toInt()).coerceAtLeast(dp(MIN_H_DP))
                    panelLp.width  = panelW
                    panelLp.height = panelH
                    panelRoot?.let { if (it.parent != null) wm.updateViewLayout(it, panelLp) }
                }
            }
            true
        }
    }

    // ─── Tab / content rendering ──────────────────────────────────────────────
    private fun selectTab(tab: Tab) {
        currentTab = tab
        tabViews.forEach { (t, v) ->
            val sel = t == tab
            v.background = ContextCompat.getDrawable(this,
                if (sel) R.drawable.bg_tab_selected else R.drawable.bg_tab_normal)
            (v as LinearLayout).apply {
                (getChildAt(0) as TextView).setTextColor(
                    if (sel) Color.parseColor("#7C4DFF") else Color.parseColor("#9090B0"))
                (getChildAt(1) as TextView).setTextColor(
                    if (sel) Color.WHITE else Color.parseColor("#9090B0"))
            }
        }
        contentList.removeAllViews()
        val list = features[tab] ?: return
        val safe   = list.filter { it.risk == Risk.SAFE   }
        val risk   = list.filter { it.risk == Risk.RISK   }
        val danger = list.filter { it.risk == Risk.DANGER }
        if (safe.isNotEmpty()) {
            section("SAFE", "#00E676"); safe.forEach { featureCard(it) }
        }
        if (risk.isNotEmpty()) {
            if (safe.isNotEmpty()) contentList.addView(divH())
            section("RISK", "#FFD740"); risk.forEach { featureCard(it) }
        }
        if (danger.isNotEmpty()) {
            if (safe.isNotEmpty() || risk.isNotEmpty()) contentList.addView(divH())
            section("DANGER", "#FF1744"); danger.forEach { featureCard(it) }
        }
    }

    private fun section(label: String, hex: String) {
        contentList.addView(TextView(this).apply {
            text = "▸  $label"
            setTextColor(Color.parseColor(hex))
            textSize = 9f; letterSpacing = 0.2f
            setPadding(dp(4), dp(6), 0, dp(4))
        })
    }

    private fun featureCard(f: Feature) {
        val bgRes    = when (f.risk) { Risk.SAFE -> R.drawable.bg_feature_safe; Risk.RISK -> R.drawable.bg_feature_risk; else -> R.drawable.bg_feature_danger }
        val badgeRes = when (f.risk) { Risk.SAFE -> R.drawable.bg_badge_safe;   Risk.RISK -> R.drawable.bg_badge_risk;   else -> R.drawable.bg_badge_danger }
        val badgeClr = when (f.risk) { Risk.SAFE -> "#00E676"; Risk.RISK -> "#FFD740"; else -> "#FF1744" }
        val badgeTxt = when (f.risk) { Risk.SAFE -> "SAFE";    Risk.RISK -> "RISK";    else -> "HOT" }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = ContextCompat.getDrawable(this@ZxOverlayService, bgRes)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
            ).also { it.bottomMargin = dp(4) }
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
        }
        row.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            addView(TextView(this@ZxOverlayService).apply {
                text = f.name; setTextColor(Color.WHITE); textSize = 12f
            })
            addView(TextView(this@ZxOverlayService).apply {
                text = badgeTxt; setTextColor(Color.parseColor(badgeClr)); textSize = 8f
                background = ContextCompat.getDrawable(this@ZxOverlayService, badgeRes)
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT
                ).also { it.topMargin = dp(2) }
                setPadding(dp(5), dp(2), dp(5), dp(2))
            })
        })

        val sw = Switch(this).apply {
            isChecked = false
            trackDrawable = ContextCompat.getDrawable(this@ZxOverlayService, R.drawable.sel_switch_track)
            setOnCheckedChangeListener { _, on -> ZxEngine.toggle(f.cmd, on) }
        }
        switchMap[f.cmd] = sw
        row.addView(sw)
        card.addView(row)

        if (f.hasSlider) {
            val slRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT
                ).also { it.topMargin = dp(6) }
            }
            val valTv = TextView(this).apply {
                text = "${f.sliderDefault}${f.sliderLabel}"
                setTextColor(Color.parseColor("#7C4DFF")); textSize = 10f; minWidth = dp(36)
            }
            slRow.addView(SeekBar(this).apply {
                max = f.sliderMax - f.sliderMin
                progress = f.sliderDefault - f.sliderMin
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                progressDrawable = null; thumb = null
                setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                    override fun onProgressChanged(sb: SeekBar, p: Int, fromUser: Boolean) {
                        valTv.text = "${p + f.sliderMin}${f.sliderLabel}"
                        if (fromUser) ZxEngine.setIntensity(f.cmd, p * 100 / (f.sliderMax - f.sliderMin).coerceAtLeast(1))
                    }
                    override fun onStartTrackingTouch(sb: SeekBar) {}
                    override fun onStopTrackingTouch(sb: SeekBar) {}
                })
            })
            slRow.addView(valTv)
            card.addView(slRow)
        }
        contentList.addView(card)
    }

    // ─── Dividers ─────────────────────────────────────────────────────────────
    private fun divH() = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
        setBackgroundColor(Color.parseColor("#1E1E3A"))
    }
    private fun divV() = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(dp(1), LinearLayout.LayoutParams.MATCH_PARENT)
        setBackgroundColor(Color.parseColor("#1E1E3A"))
    }

    // ─── Status API ───────────────────────────────────────────────────────────
    fun setConnected(pid: Int) = statusDot.post {
        statusDot.background = ContextCompat.getDrawable(this, R.drawable.bg_status_dot_on)
        statusText.text = "PID $pid"
        statusText.setTextColor(Color.parseColor("#00E676"))
    }

    // ─── Utils ────────────────────────────────────────────────────────────────
    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun secureOverlayLp(w: Int, h: Int) = WindowManager.LayoutParams(
        w, h,
        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
        WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE       or
        WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL     or
        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN    or
        WindowManager.LayoutParams.FLAG_SECURE,
        PixelFormat.TRANSLUCENT
    ).also { it.gravity = Gravity.TOP or Gravity.START }
}
