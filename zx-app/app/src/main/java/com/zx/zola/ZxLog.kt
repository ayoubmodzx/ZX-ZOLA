package com.zx.zola

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

object ZxLog {
    private const val MAX = 60

    data class Entry(val ts: String, val level: Char, val msg: String)

    private val entries = CopyOnWriteArrayList<Entry>()
    private val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    fun i(msg: String) = add('I', msg)
    fun w(msg: String) = add('W', msg)
    fun e(msg: String) = add('E', msg)
    // Module logcat lines — shown with [MOD] prefix so they're distinct from app events
    fun module(msg: String, level: Char = 'I') = add(level, "[MOD] $msg")

    private fun add(level: Char, msg: String) {
        val ts = synchronized(fmt) { fmt.format(Date()) }
        entries.add(Entry(ts, level, msg))
        while (entries.size > MAX) entries.removeAt(0)
    }

    fun snapshot(): List<Entry> = entries.toList()

    fun clear() = entries.clear()
}
