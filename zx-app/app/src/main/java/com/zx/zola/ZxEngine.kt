package com.zx.zola

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.*
import java.io.DataOutputStream
import java.io.File
import java.util.concurrent.TimeUnit

private const val TAG    = "ZX-ENGINE"
private const val FF_PKG  = "com.dts.freefireth"
private const val FF_PKG2 = "com.dts.freefiremax"

object Cmd {
    const val ANTI_RECOIL    = 1;  const val NO_SPREAD      = 2
    const val RAPID_FIRE     = 3;  const val WIDE_POV       = 4
    const val ESP            = 5;  const val SPEED_HACK     = 6
    const val HIGH_JUMP      = 7;  const val VEHICLE_SPEED  = 8
    const val RAPID_FIRE_RISK= 9;  const val NO_GRASS       = 10
    const val ANTI_DAMAGE    = 11
    // Aim system — uses setIntensity for bone/fov/smooth params
    const val AIM_ENABLE     = 12
    const val AIM_BONE       = 13  // intensity: 0=AI, 1=NECK, 2=HEAD
    const val AIM_FOV        = 14  // intensity: 5-90 degrees
    const val AIM_SMOOTH     = 15  // intensity: 0-100 smoothness
}

object ZxEngine {

    // Single-thread dispatcher guarantees toggle/intensity commands arrive in order
    private val ioSerial   = Dispatchers.IO.limitedParallelism(1)
    private val scope      = CoroutineScope(ioSerial + SupervisorJob())
    private var injPath    = ""
    private var payloadLib = ""
    private val PREFS_KEY  = "zx_inj_ver"

    fun init(context: Context) {
        // Dispatch disk I/O off the main thread
        CoroutineScope(Dispatchers.IO).launch {
            payloadLib = "${context.applicationInfo.nativeLibraryDir}/libzx_payload.so"
            injPath    = extractInjector(context)
            Log.i(TAG, "injector=$injPath  payload=$payloadLib")
        }
    }

    fun toggle(cmd: Int, enable: Boolean) {
        scope.launch {
            val pid  = findFfPid() ?: run { Log.e(TAG, "FF not running"); return@launch }
            val flag = if (enable) 1 else 0
            // Quote paths to survive spaces in nativeLibraryDir (e.g. ~~base64== paths)
            val out  = runRoot("'$injPath' $pid $cmd $flag '$payloadLib' 0")
            Log.i(TAG, "toggle cmd=$cmd enable=$enable => $out")
        }
    }

    fun setIntensity(cmd: Int, intensity: Int) {
        scope.launch {
            val pid = findFfPid() ?: return@launch
            val out = runRoot("'$injPath' $pid $cmd 1 '$payloadLib' $intensity")
            Log.i(TAG, "intensity cmd=$cmd intensity=$intensity => $out")
        }
    }

    fun isFfRunning(): Boolean = findFfPid() != null

    private fun findFfPid(): Int? = try {
        val out = runRoot("pidof $FF_PKG || pidof $FF_PKG2").trim()
        // Take lowest PID (parent process) — some BusyBox versions return highest first
        out.split("\\s+".toRegex()).mapNotNull { it.toIntOrNull() }.minOrNull()
    } catch (e: Exception) { null }

    private fun runRoot(cmd: String): String = try {
        val proc = Runtime.getRuntime().exec("su")
        DataOutputStream(proc.outputStream).also {
            it.writeBytes("$cmd\n"); it.writeBytes("exit\n"); it.flush()
        }
        val finished = proc.waitFor(10L, TimeUnit.SECONDS)
        if (!finished) { proc.destroyForcibly(); Log.e(TAG, "root exec timeout: $cmd") }
        proc.inputStream.bufferedReader().readText()
    } catch (e: Exception) { Log.e(TAG, "root exec: $e"); "" }

    private fun extractInjector(ctx: Context): String {
        val dest    = File(ctx.filesDir, "zx_injector")
        val prefs   = ctx.getSharedPreferences("zx_prefs", 0)
        val storedV = prefs.getInt(PREFS_KEY, -1)
        val currentV = try { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionCode } catch (_: Exception) { 0 }
        if (!dest.exists() || dest.length() == 0L || storedV != currentV) {
            try {
                ctx.assets.open("arm64-v8a/zx_injector").use { inp ->
                    dest.outputStream().use { inp.copyTo(it) }
                }
                dest.setExecutable(true, false)
                prefs.edit().putInt(PREFS_KEY, currentV).apply()
            } catch (e: Exception) {
                Log.e(TAG, "extract injector failed: $e")
            }
        }
        return dest.absolutePath
    }
}
