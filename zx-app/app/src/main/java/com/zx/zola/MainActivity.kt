package com.zx.zola

import android.content.*
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    private val OVERLAY_REQ = 100

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        ZxEngine.init(this)

        val statusTv    = findViewById<TextView>(R.id.tv_status)
        val activateBtn = findViewById<Button>(R.id.btn_activate)
        val stopBtn     = findViewById<Button>(R.id.btn_stop)

        activateBtn.setOnClickListener {
            if (!Settings.canDrawOverlays(this)) {
                requestOverlayPermission()
                return@setOnClickListener
            }
            if (!ZxEngine.isFfRunning()) {
                Toast.makeText(this, "Open Free Fire first", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            startFg()
            statusTv.text = "● ACTIVE"
            statusTv.setTextColor(getColor(android.R.color.holo_red_light))
        }

        stopBtn.setOnClickListener {
            stopFg()
            statusTv.text = "● INACTIVE"
            statusTv.setTextColor(getColor(android.R.color.darker_gray))
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
