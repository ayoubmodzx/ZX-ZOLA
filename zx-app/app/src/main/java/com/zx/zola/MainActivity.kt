package com.zx.zola

import android.content.*
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.switchmaterial.SwitchMaterial

class MainActivity : AppCompatActivity() {

    private val OVERLAY_REQ = 100
    private val handler = Handler(Looper.getMainLooper())
    private var isActive = false

    // Feature switch → Cmd constant mapping
    private val featureMap = mapOf(
        R.id.sw_aim_assist  to Cmd.AIM_ASSIST,
        R.id.sw_headshot    to Cmd.HEADSHOT_ASSIST,
        R.id.sw_wide_pov    to Cmd.WIDE_POV,
        R.id.sw_anti_recoil to Cmd.ANTI_RECOIL,
        R.id.sw_no_spread   to Cmd.NO_SPREAD,
        R.id.sw_rapid_fire  to Cmd.RAPID_FIRE,
        R.id.sw_esp         to Cmd.ESP
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        ZxEngine.init(this)

        val activateBtn  = findViewById<Button>(R.id.btn_activate)
        val stopBtn      = findViewById<Button>(R.id.btn_stop)

        activateBtn.setOnClickListener {
            if (!Settings.canDrawOverlays(this)) {
                requestOverlayPermission(); return@setOnClickListener
            }
            if (!ZxEngine.isFfRunning()) {
                Toast.makeText(this, "Launch Free Fire first", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            startFg()
            setActive(true)
        }

        stopBtn.setOnClickListener {
            stopFg()
            setActive(false)
        }

        // Wire all feature switches
        featureMap.forEach { (viewId, cmd) ->
            findViewById<SwitchMaterial>(viewId).setOnCheckedChangeListener { _, checked ->
                if (isActive) ZxEngine.toggle(cmd, checked)
                else if (checked) Toast.makeText(this, "Activate mod first", Toast.LENGTH_SHORT).show()
                    .also { (it as? Unit); findViewById<SwitchMaterial>(viewId).isChecked = false }
            }
        }
    }

    private fun setActive(active: Boolean) {
        isActive = active
        val statusCard = findViewById<View>(R.id.card_status)
        val dot        = findViewById<View>(R.id.dot_status)
        val tv         = findViewById<TextView>(R.id.tv_status)
        val tvSub      = findViewById<TextView>(R.id.tv_status_sub)

        if (active) {
            statusCard.setBackgroundResource(R.drawable.bg_status_active)
            dot.setBackgroundColor(getColor(R.color.zx_purple))
            tv.text = "ACTIVE"
            tv.setTextColor(getColor(R.color.zx_purple))
            tvSub.text = "Injected"
        } else {
            statusCard.setBackgroundResource(R.drawable.bg_status_inactive)
            dot.setBackgroundColor(getColor(R.color.zx_text_muted))
            tv.text = "INACTIVE"
            tv.setTextColor(getColor(R.color.zx_text_dim))
            tvSub.text = "Ready"
            // Reset all switches when deactivating
            featureMap.keys.forEach { id ->
                findViewById<SwitchMaterial>(id).isChecked = false
            }
        }
    }

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        super.onActivityResult(req, res, data)
        if (req == OVERLAY_REQ && Settings.canDrawOverlays(this)) startFg()
    }

    private fun startFg() = ContextCompat.startForegroundService(
        this, Intent(this, ZxOverlayService::class.java))

    private fun stopFg() = stopService(Intent(this, ZxOverlayService::class.java))

    private fun requestOverlayPermission() = startActivityForResult(
        Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
               Uri.parse("package:$packageName")), OVERLAY_REQ)
}
