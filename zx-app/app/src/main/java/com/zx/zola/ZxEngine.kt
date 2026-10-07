package com.zx.zola

import android.content.Context
import android.util.Log
import kotlinx.coroutines.*
import java.io.DataOutputStream
import java.io.File

private const val TAG    = "ZX-ENGINE"
private const val FF_PKG  = "com.dts.freefireth"
private const val FF_PKG2 = "com.dts.freefiremax"

object Cmd {
    const val ANTI_RECOIL    = 1;  const val NO_SPREAD      = 2
    const val RAPID_FIRE     = 3;  const val AIM_ASSIST     = 4
    const val WIDE_POV       = 5;  const val ESP            = 6
    const val HEADSHOT_ASSIST= 7
}

object ZxEngine {

    private val scope      = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var injPath    = ""   // path to extracted zx_injector binary
    private var payloadLib = ""   // path to libzx_payload.so installed by APK

    fun init(context: Context) {
        // libzx_payload.so is installed by Android to nativeLibraryDir
        payloadLib = "${context.applicationInfo.nativeLibraryDir}/libzx_payload.so"
        injPath    = extractInjector(context)
        Log.i(TAG, "injector=$injPath  payload=$payloadLib")
    }

    fun toggle(cmd: Int, enable: Boolean) {
        scope.launch {
            val pid = findFfPid() ?: run {
                Log.e(TAG, "FF not running"); return@launch
            }
            val flag = if (enable) 1 else 0
            val out  = runRoot("$injPath $pid $cmd $flag $payloadLib")
            Log.i(TAG, "toggle cmd=$cmd enable=$enable => $out")
        }
    }

    fun isFfRunning(): Boolean = findFfPid() != null

    private fun findFfPid(): Int? = try {
        val out = runRoot("pidof $FF_PKG || pidof $FF_PKG2").trim()
        out.split("\\s+".toRegex()).firstOrNull()?.toIntOrNull()
    } catch (e: Exception) { null }

    private fun runRoot(cmd: String): String = try {
        val proc = Runtime.getRuntime().exec("su")
        DataOutputStream(proc.outputStream).also {
            it.writeBytes("$cmd\n"); it.writeBytes("exit\n"); it.flush()
        }
        proc.waitFor()
        proc.inputStream.bufferedReader().readText()
    } catch (e: Exception) { Log.e(TAG, "root exec: $e"); "" }

    private fun extractInjector(ctx: Context): String {
        val dest = File(ctx.filesDir, "zx_injector")
        if (!dest.exists() || dest.length() == 0L) {
            try {
                ctx.assets.open("arm64-v8a/zx_injector").use { inp ->
                    dest.outputStream().use { inp.copyTo(it) }
                }
                dest.setExecutable(true, false)
            } catch (e: Exception) {
                Log.e(TAG, "extract injector failed: $e")
            }
        }
        return dest.absolutePath
    }
}
