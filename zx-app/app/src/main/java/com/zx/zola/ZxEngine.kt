package com.zx.zola

import android.content.Context
import android.util.Log

object ZxEngine {

    object Cmd {
        // WEAPON — SAFE
        const val ANTI_RECOIL       = 1
        const val NO_SPREAD         = 2
        // WEAPON — RISK
        const val RAPID_FIRE        = 3
        const val RAPID_FIRE_RISK   = 9
        // WEAPON — DANGER
        const val INFINITE_AMMO     = 17
        const val NO_RELOAD         = 18
        const val WALL_SHOOT        = 27

        // AIM — RISK
        const val AIM_ENABLE        = 12
        const val AIM_BONE          = 13
        const val AIM_FOV           = 14
        const val AIM_SMOOTH        = 15
        const val AUTO_HEADSHOT     = 23
        // AIM — DANGER
        const val SILENT_AIM        = 22
        const val FULL_AIMBOT       = 24
        const val ANTI_AIM          = 25

        // MOVEMENT — RISK
        const val SPEED_HACK        = 6
        const val HIGH_JUMP         = 7
        const val VEHICLE_SPEED     = 8
        // MOVEMENT — DANGER
        const val NOCLIP            = 19
        const val TELEPORT          = 20
        const val TELEPORT_SAVE     = 21

        // SURVIVAL — RISK
        const val ANTI_DAMAGE       = 11
        const val AUTO_REVIVE       = 26
        // SURVIVAL — DANGER
        const val GOD_MODE          = 16

        // VISUAL — SAFE
        const val WIDE_POV          = 4
        const val NO_GRASS          = 10
        const val ESP               = 5
    }

    private var targetPid: Int = -1
    private var payloadPath: String = "/data/local/tmp/libzx_payload.so"
    private val cmdLock = Any()

    fun init(context: Context) {
        val payloadFile = context.getFileStreamPath("libzx_payload.so")
        if (payloadFile.exists()) payloadPath = payloadFile.absolutePath
    }

    fun isFfRunning(): Boolean = try {
        val proc = Runtime.getRuntime().exec(
            arrayOf("su", "-c",
                "pidof com.dts.freefireth 2>/dev/null || pidof com.garena.game.fftw 2>/dev/null"))
        val out = proc.inputStream.bufferedReader().readText().trim()
        proc.waitFor()
        if (out.isNotEmpty()) { targetPid = out.trim().split(" ")[0].toIntOrNull() ?: -1 }
        out.isNotEmpty()
    } catch (e: Exception) { false }

    fun setTarget(pid: Int, path: String) {
        targetPid = pid
        payloadPath = path
    }

    fun toggle(cmd: Int, on: Boolean, intensity: Int = 0) {
        if (targetPid <= 0) return
        synchronized(cmdLock) {
            try {
                val en = if (on) 1 else 0
                val args = "$targetPid $cmd $en $payloadPath $intensity"
                Runtime.getRuntime().exec(arrayOf("su", "-c", "zx_injector $args")).waitFor()
            } catch (e: Exception) {
                Log.e("ZxEngine", "toggle failed: ${e.message}")
            }
        }
    }

    fun setIntensity(cmd: Int, pct: Int) {
        toggle(cmd, true, pct)
    }
}
