package com.zx.zola

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import java.io.File

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
    private var payloadPath: String = ""
    private var injectorPath: String = ""
    private val cmdLock = Any()
    private val bgThread = HandlerThread("zx-engine").also { it.start() }
    private val bgHandler = Handler(bgThread.looper)

    fun init(context: Context) {
        val appCtx = context.applicationContext
        val libDir = appCtx.applicationInfo.nativeLibraryDir
        payloadPath  = File(libDir, "libunity_render.so").absolutePath
        injectorPath = File(libDir, "libunity_ndk.so").absolutePath
        Log.i("ZxEngine", "injector=$injectorPath  payload=$payloadPath")
        ZxLog.i("libDir: $libDir")
        ZxLog.i("injector: $injectorPath")
        ZxLog.i("  exists=${File(injectorPath).exists()}  exec=${File(injectorPath).canExecute()}")
        ZxLog.i("payload: $payloadPath")
        ZxLog.i("  exists=${File(payloadPath).exists()}")
    }

    fun isFfRunning(): Boolean = try {
        val proc = Runtime.getRuntime().exec(
            arrayOf("su", "-c",
                "pidof com.dts.freefireth 2>/dev/null || pidof com.garena.game.fftw 2>/dev/null"))
        val out = proc.inputStream.bufferedReader().readText().trim()
        proc.waitFor()
        if (out.isNotEmpty()) { targetPid = out.trim().split(" ")[0].toIntOrNull() ?: -1 }
        else { targetPid = -1 }
        out.isNotEmpty()
    } catch (e: Exception) { false }

    fun getTargetPid(): Int = targetPid

    fun setTarget(pid: Int, path: String) {
        targetPid = pid
        payloadPath = path
    }

    fun toggle(cmd: Int, on: Boolean, intensity: Int = 0) {
        if (targetPid <= 0) {
            ZxLog.w("skip cmd=$cmd: pid not set")
            return
        }
        val injector = injectorPath
        if (injector.isEmpty()) {
            ZxLog.w("skip cmd=$cmd: injectorPath empty")
            return
        }
        val payload = payloadPath
        bgHandler.post {
            synchronized(cmdLock) {
                try {
                    val en = if (on) 1 else 0
                    // Quote both paths — nativeLibraryDir contains ~~hash==/ on Android 12+
                    val cmd2 = "'$injector' $targetPid $cmd $en '$payload' $intensity"
                    ZxLog.i("exec cmd=$cmd on=$on pid=$targetPid")
                    val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd2))
                    val stdout = proc.inputStream.bufferedReader().readText().trim()
                    val stderr = proc.errorStream.bufferedReader().readText().trim()
                    val rc = proc.waitFor()
                    Log.i("ZxEngine", "toggle cmd=$cmd on=$on rc=$rc")
                    ZxLog.i("rc=$rc cmd=$cmd on=$on")
                    if (stdout.isNotEmpty()) ZxLog.i("out: $stdout")
                    if (stderr.isNotEmpty()) ZxLog.e("err: $stderr")
                } catch (e: Exception) {
                    Log.e("ZxEngine", "toggle failed: ${e.message}")
                    ZxLog.e("ex: ${e.message}")
                }
            }
        }
    }

    fun setIntensity(cmd: Int, pct: Int) {
        toggle(cmd, true, pct)
    }
}
