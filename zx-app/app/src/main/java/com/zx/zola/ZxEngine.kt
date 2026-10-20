package com.zx.zola

import android.content.Context
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import java.io.File
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicReference

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

    private var clientBinPath: String = ""
    private var targetPid: Int = -1

    private val bgThread = HandlerThread("zx-engine").also { it.start() }
    private val bgHandler = Handler(bgThread.looper)

    // Persistent zx_client --loop process
    private val clientProc  = AtomicReference<Process?>(null)
    private val clientStdin = AtomicReference<OutputStream?>(null)

    var onStatusUpdate: ((cmd: Int, ok: Boolean, msg: String) -> Unit)? = null

    fun init(context: Context) {
        val libDir = context.applicationContext.applicationInfo.nativeLibraryDir
        clientBinPath = File(libDir, "libzx_client.so").absolutePath
        ZxLog.i("zx_client: $clientBinPath  exists=${File(clientBinPath).exists()}")
    }

    fun isFfRunning(): Boolean = try {
        val proc = Runtime.getRuntime().exec(
            arrayOf("su", "-c",
                "pidof com.dts.freefireth 2>/dev/null || pidof com.garena.game.fftw 2>/dev/null"))
        val out = proc.inputStream.bufferedReader().readText().trim()
        proc.waitFor()
        if (out.isNotEmpty()) targetPid = out.trim().split(" ")[0].toIntOrNull() ?: -1
        else targetPid = -1
        out.isNotEmpty()
    } catch (e: Exception) { false }

    fun getTargetPid(): Int = targetPid

    // Start the persistent zx_client --loop process (called once when FF is detected)
    fun connect() {
        bgHandler.post {
            if (clientProc.get()?.let { isAlive(it) } == true) return@post
            val bin = clientBinPath
            if (bin.isEmpty() || !File(bin).exists()) {
                ZxLog.e("zx_client not found: $bin")
                onStatusUpdate?.invoke(0, false, "binary missing")
                return@post
            }
            try {
                ZxLog.i("starting zx_client --loop")
                val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "'$bin' --loop"))
                clientProc.set(proc)
                clientStdin.set(proc.outputStream)
                // Drain stderr in background so it doesn't block
                Thread {
                    proc.errorStream.bufferedReader().forEachLine { ZxLog.i("cli: $it") }
                }.also { it.isDaemon = true }.start()
                ZxLog.i("zx_client --loop started (pid=$targetPid)")
                onStatusUpdate?.invoke(0, true, "connected")
            } catch (e: Exception) {
                ZxLog.e("connect failed: ${e.message}")
                onStatusUpdate?.invoke(0, false, e.message ?: "exception")
            }
        }
    }

    fun disconnect() {
        bgHandler.post {
            clientProc.getAndSet(null)?.destroy()
            clientStdin.getAndSet(null)
            ZxLog.i("zx_client disconnected")
        }
    }

    // Send a feature command.  intensity is the raw display value (angle, %, or raw).
    fun toggle(cmd: Int, on: Boolean, intensity: Int = 0) {
        bgHandler.post {
            val en  = if (on) 1 else 0
            val flt = intensity.toFloat()
            val line = if (intensity != 0) "$cmd $en $flt\n" else "$cmd $en\n"
            if (!writeLine(line)) {
                // Pipe died — reconnect once and retry
                ZxLog.w("pipe dead — reconnecting")
                reconnect()
                writeLine(line)
            }
            ZxLog.i("cmd=$cmd on=$on intensity=$intensity")
            onStatusUpdate?.invoke(cmd, true, if (on) "ON" else "OFF")
        }
    }

    fun setIntensity(cmd: Int, pct: Int) = toggle(cmd, true, pct)

    // ── Private ──────────────────────────────────────────────────────────────

    private fun writeLine(line: String): Boolean {
        return try {
            val out = clientStdin.get() ?: return false
            out.write(line.toByteArray(Charsets.UTF_8))
            out.flush()
            true
        } catch (e: Exception) {
            clientStdin.set(null)
            clientProc.set(null)
            false
        }
    }

    private fun reconnect() {
        clientProc.getAndSet(null)?.destroy()
        clientStdin.set(null)
        val bin = clientBinPath
        if (bin.isEmpty() || !File(bin).exists()) return
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "'$bin' --loop"))
            clientProc.set(proc)
            clientStdin.set(proc.outputStream)
            Thread {
                proc.errorStream.bufferedReader().forEachLine { ZxLog.i("cli: $it") }
            }.also { it.isDaemon = true }.start()
            ZxLog.i("reconnected zx_client --loop")
        } catch (e: Exception) {
            ZxLog.e("reconnect failed: ${e.message}")
        }
    }

    private fun isAlive(p: Process): Boolean = try {
        p.exitValue(); false
    } catch (e: IllegalThreadStateException) { true }
}
