package com.zx.zola

import java.util.concurrent.atomic.AtomicReference

object LogcatReader {

    data class ModuleStatus(
        val injected : Boolean = false,  // "Free Fire detected" in ZX-ZOLA
        val anosdk1  : Boolean = false,  // "Phase 1 early hooks" with exit=1
        val anosdk2  : Boolean = false,  // "Phase 2: API hooks installed"
        val il2cpp   : Boolean = false,  // "resolved Player:" with non-null ptr
        val socket   : Boolean = false   // "Socket server listening"
    ) {
        val allGood get() = injected && anosdk1 && anosdk2 && il2cpp && socket
    }

    private val _status = AtomicReference(ModuleStatus())
    val status: ModuleStatus get() = _status.get()

    @Volatile private var proc: Process? = null
    @Volatile private var running = false

    // Start reading module logcat via root shell.
    // Feeds parsed lines into ZxLog and updates ModuleStatus.
    fun start() {
        if (running) return
        running = true
        _status.set(ModuleStatus())

        Thread {
            runCatching {
                val p = Runtime.getRuntime().exec(
                    arrayOf("su", "-c",
                        "logcat -v time -s ZX-ZOLA:V ZX-FEAT:V ZX-ANO:V ZX-CLIENT:V"))
                proc = p
                p.inputStream.bufferedReader().forEachLine { raw ->
                    if (!running) return@forEachLine
                    parseLine(raw)
                }
            }
            running = false
        }.also { it.isDaemon = true; it.name = "zx-logcat" }.start()
    }

    fun stop() {
        running = false
        proc?.destroy()
        proc = null
    }

    // Reset status between FF sessions
    fun reset() = _status.set(ModuleStatus())

    // logcat -v time line format:
    //   MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: message
    private val TAG_SUFFIX = Regex("""ZX-(?:ZOLA|FEAT|ANO|CLIENT): (.+)""")

    private fun parseLine(raw: String) {
        val m = TAG_SUFFIX.find(raw) ?: return
        val msg = m.groupValues[1].trim()

        // Level: look for " I ", " W ", " E " before the tag
        val level = when {
            " E ZX-" in raw -> 'E'
            " W ZX-" in raw -> 'W'
            else             -> 'I'
        }

        ZxLog.module(msg, level)
        updateStatus(msg)
    }

    private fun updateStatus(msg: String) {
        val s = _status.get()
        val updated = s.copy(
            injected = s.injected || "Free Fire detected" in msg,
            anosdk1  = s.anosdk1  || ("Phase 1 early hooks" in msg && "kill=1" in msg),
            anosdk2  = s.anosdk2  || "Phase 2: API hooks installed" in msg,
            il2cpp   = s.il2cpp   || (
                "resolved Player" in msg &&
                "Player:0x0" !in msg &&
                "0x0000000000000000" !in msg
            ),
            socket   = s.socket   || "Socket server listening" in msg
        )
        if (updated != s) _status.set(updated)
    }
}
