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
import com.google.android.material.slider.Slider
import com.google.android.material.switchmaterial.SwitchMaterial

class MainActivity : AppCompatActivity() {

    private val OVERLAY_REQ = 100
    private val handler = Handler(Looper.getMainLooper())
    private var isActive = false

    // Feature switch → Cmd constant mapping (standard features)
    private val featureMap = mapOf(
        R.id.sw_aim_assist  to Cmd.AIM_ASSIST,
        R.id.sw_headshot    to Cmd.HEADSHOT_ASSIST,
        R.id.sw_wide_pov    to Cmd.WIDE_POV,
        R.id.sw_anti_recoil to Cmd.ANTI_RECOIL,
        R.id.sw_no_spread   to Cmd.NO_SPREAD,
        R.id.sw_rapid_fire  to Cmd.RAPID_FIRE,
        R.id.sw_esp         to Cmd.ESP
    )

    // Risk feature: switch → (Cmd, sliderRowId, sliderId, valueLabelId)
    data class RiskFeature(val cmd: Int, val rowId: Int, val sliderId: Int, val valueLabelId: Int)
    private val riskFeatures = listOf(
        RiskFeature(Cmd.SPEED_HACK,     R.id.row_speed_slider,   R.id.sl_speed,   R.id.tv_speed_val),
        RiskFeature(Cmd.RAPID_FIRE_RISK,R.id.row_rapid_slider,   R.id.sl_rapid,   R.id.tv_rapid_val),
        RiskFeature(Cmd.VEHICLE_SPEED,  R.id.row_vehicle_slider, R.id.sl_vehicle, R.id.tv_vehicle_val),
        RiskFeature(Cmd.HIGH_JUMP,      R.id.row_jump_slider,    R.id.sl_jump,    R.id.tv_jump_val)
    )
    private val riskSwitchIds = listOf(
        R.id.sw_speed_hack, R.id.sw_rapid_fire_risk, R.id.sw_vehicle_speed, R.id.sw_high_jump
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

        // Wire all standard feature switches
        featureMap.forEach { (viewId, cmd) ->
            findViewById<SwitchMaterial>(viewId).setOnCheckedChangeListener { _, checked ->
                if (isActive) ZxEngine.toggle(cmd, checked)
                else if (checked) Toast.makeText(this, "Activate mod first", Toast.LENGTH_SHORT).show()
                    .also { (it as? Unit); findViewById<SwitchMaterial>(viewId).isChecked = false }
            }
        }

        // Wire risk feature switches + sliders
        riskSwitchIds.forEachIndexed { idx, switchId ->
            val rf = riskFeatures[idx]
            val sw  = findViewById<SwitchMaterial>(switchId)
            val row = findViewById<View>(rf.rowId)
            val sl  = findViewById<Slider>(rf.sliderId)
            val tv  = findViewById<TextView>(rf.valueLabelId)

            sw.setOnCheckedChangeListener { _, checked ->
                if (!isActive && checked) {
                    Toast.makeText(this, "Activate mod first", Toast.LENGTH_SHORT).show()
                    sw.isChecked = false
                    return@setOnCheckedChangeListener
                }
                row.visibility = if (checked) View.VISIBLE else View.GONE
                ZxEngine.toggle(rf.cmd, checked)
                if (!checked) {
                    sl.value = 0f
                    tv.text = "0%"
                }
            }

            sl.addOnChangeListener { _, value, fromUser ->
                if (!fromUser) return@addOnChangeListener
                val pct = value.toInt()
                tv.text = "$pct%"
                ZxEngine.setIntensity(rf.cmd, pct)
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
            featureMap.keys.forEach { id ->
                findViewById<SwitchMaterial>(id).isChecked = false
            }
            // Reset risk switches + hide sliders
            riskSwitchIds.forEachIndexed { idx, switchId ->
                val rf = riskFeatures[idx]
                findViewById<SwitchMaterial>(switchId).isChecked = false
                findViewById<View>(rf.rowId).visibility = View.GONE
                findViewById<Slider>(rf.sliderId).value = 0f
                findViewById<TextView>(rf.valueLabelId).text = "0%"
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
