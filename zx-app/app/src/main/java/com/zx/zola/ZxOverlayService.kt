package com.zx.zola

import android.app.*
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.IBinder
import android.view.*
import android.widget.*
import androidx.core.app.NotificationCompat

class ZxOverlayService : Service() {

    private lateinit var wm: WindowManager
    private lateinit var root: View
    private var expanded = true

    // Feature state: cmd -> enabled
    private val state = mutableMapOf<Int, Boolean>()

    private val features = listOf(
        // category, name, cmd
        Triple("COMBAT",   "Anti Recoil",   Cmd.ANTI_RECOIL),
        Triple("COMBAT",   "No Spread",     Cmd.NO_SPREAD),
        Triple("COMBAT",   "Rapid Fire",    Cmd.RAPID_FIRE),
        Triple("COMBAT",   "Aim Assist",    Cmd.AIM_ASSIST),
        Triple("MOVEMENT", "Speed Hack",    Cmd.SPEED_HACK),
        Triple("MOVEMENT", "High Jump",     Cmd.HIGH_JUMP),
        Triple("MOVEMENT", "Vehicle Speed", Cmd.VEHICLE_SPEED),
        Triple("VISUAL",   "Wide POV",      Cmd.WIDE_POV),
        Triple("VISUAL",   "No Grass",      Cmd.NO_GRASS),
        Triple("SURVIVAL", "Max Health",    Cmd.MAX_HEALTH),
        Triple("SURVIVAL", "Anti Damage",   Cmd.ANTI_DAMAGE),
    )

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        startForeground(1, buildNotification())
        wm = getSystemService(WINDOW_SERVICE) as WindowManager
        buildOverlay()
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { wm.removeView(root) }
    }

    private fun buildOverlay() {
        val ctx = this

        // Root frame
        val frame = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 12, 16, 12)
            setBackgroundColor(0xCC0A0A0A.toInt())
        }

        // Header row — ZX logo + collapse toggle
        val header = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val logo = TextView(ctx).apply {
            text = "⚡ ZX-ZOLA"
            setTextColor(Color.parseColor("#FF4444"))
            textSize = 15f
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        }
        val collapseBtn = TextView(ctx).apply {
            text = "▲"
            setTextColor(Color.WHITE)
            textSize = 13f
            setPadding(12, 0, 0, 0)
            setOnClickListener { toggleExpand(frame) }
        }
        header.addView(logo)
        header.addView(collapseBtn)
        frame.addView(header)

        // Feature list
        val featureContainer = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            tag = "features"
        }

        var lastCategory = ""
        for ((category, name, cmd) in features) {
            // Category label
            if (category != lastCategory) {
                featureContainer.addView(TextView(ctx).apply {
                    text = "── $category"
                    setTextColor(Color.parseColor("#888888"))
                    textSize = 10f
                    setPadding(0, 8, 0, 2)
                })
                lastCategory = category
            }

            // Feature row: name + switch
            val row = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, 4, 0, 4)
            }
            val label = TextView(ctx).apply {
                text = name
                setTextColor(Color.WHITE)
                textSize = 13f
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            }
            val sw = Switch(ctx).apply {
                isChecked = state[cmd] == true
                setOnCheckedChangeListener { _, on ->
                    state[cmd] = on
                    label.setTextColor(if (on) Color.parseColor("#FF4444") else Color.WHITE)
                    ZxEngine.toggle(cmd, on)
                }
            }
            row.addView(label)
            row.addView(sw)
            featureContainer.addView(row)
        }

        frame.addView(featureContainer)

        val params = WindowManager.LayoutParams(
            320.dp(ctx), WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = 20; y = 120
        }

        // Drag support
        var dX = 0f; var dY = 0f
        frame.setOnTouchListener { v, ev ->
            when (ev.action) {
                MotionEvent.ACTION_DOWN -> { dX = params.x - ev.rawX; dY = params.y - ev.rawY; false }
                MotionEvent.ACTION_MOVE -> {
                    params.x = (ev.rawX + dX).toInt()
                    params.y = (ev.rawY + dY).toInt()
                    wm.updateViewLayout(frame, params)
                    true
                }
                else -> false
            }
        }

        root = frame
        wm.addView(frame, params)
    }

    private fun toggleExpand(frame: LinearLayout) {
        expanded = !expanded
        val container = frame.findViewWithTag<LinearLayout>("features")
        container?.visibility = if (expanded) View.VISIBLE else View.GONE
    }

    private fun buildNotification(): Notification {
        val channelId = "zx_fg"
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(channelId, "ZX Active", NotificationManager.IMPORTANCE_LOW)
        )
        return NotificationCompat.Builder(this, channelId)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentTitle("ZX-ZOLA")
            .setContentText("Active — tap to open")
            .build()
    }

    private fun Int.dp(ctx: android.content.Context): Int =
        (this * ctx.resources.displayMetrics.density).toInt()
}
