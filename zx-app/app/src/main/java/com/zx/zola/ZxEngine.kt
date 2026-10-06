package com.zx.zola

import android.util.Log
import kotlinx.coroutines.*
import java.io.DataOutputStream
import java.io.File

private const val TAG = "ZX-ENGINE"
private const val FF_PKG  = "com.dts.freefireth"
private const val FF_PKG2 = "com.dts.freefiremax"

// Feature IDs — match native CMD_ constants in zx_payload.cpp
object Cmd {
    const val ANTI_RECOIL    = 1
    const val NO_SPREAD      = 2
    const val RAPID_FIRE     = 3
    const val AIM_ASSIST     = 4
    const val SPEED_HACK     = 5
    const val HIGH_JUMP      = 6
    const val VEHICLE_SPEED  = 7
    const val WIDE_POV       = 8
    const val NO_GRASS       = 9
    const val MAX_HEALTH     = 10
    const val ANTI_DAMAGE    = 11
}

object ZxEngine {

    private val scope   = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var libPath = ""

    // Call once from Application/MainActivity
    fun init(filesDir: File) {
        libPath = extractPayload(filesDir)
        Log.i(TAG, "Payload at: $libPath")
    }

    // Toggle a feature on/off — fires injection if FF is running
    fun toggle(cmd: Int, enable: Boolean) {
        scope.launch {
            val pid = findFfPid() ?: run {
                Log.e(TAG, "FF not running"); return@launch
            }
            val result = runRoot("${libPath} $pid $cmd ${if (enable) 1 else 0}")
            Log.i(TAG, "toggle cmd=$cmd enable=$enable result=$result")
        }
    }

    // Check if FF process is alive
    fun isFfRunning(): Boolean = findFfPid() != null

    // ── Internals ──────────────────────────────────────────────────────────────

    private fun findFfPid(): Int? {
        return try {
            val output = runRoot("pidof $FF_PKG || pidof $FF_PKG2").trim()
            output.split("\\s+".toRegex()).firstOrNull()?.toIntOrNull()
        } catch (e: Exception) { null }
    }

    private fun runRoot(cmd: String): String {
        return try {
            val proc = Runtime.getRuntime().exec("su")
            val os   = DataOutputStream(proc.outputStream)
            os.writeBytes("$cmd\n")
            os.writeBytes("exit\n")
            os.flush()
            proc.waitFor()
            proc.inputStream.bufferedReader().readText()
        } catch (e: Exception) {
            Log.e(TAG, "root exec failed: $e"); ""
        }
    }

    // Extract the native injector from jniLibs into a writable+executable path
    private fun extractPayload(dir: File): String {
        val dest = File(dir, "zx_injector")
        if (!dest.exists()) {
            ZxEngine::class.java.classLoader
                ?.getResourceAsStream("lib/arm64-v8a/libzx_injector.so")
                ?.use { input -> dest.outputStream().use { input.copyTo(it) } }
            dest.setExecutable(true, false)
        }
        return dest.absolutePath
    }
}
