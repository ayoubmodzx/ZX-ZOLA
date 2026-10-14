package com.zx.zola

import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Spannable
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean

class LogConsoleActivity : AppCompatActivity() {

    private val running = AtomicBoolean(false)
    private var logProcess: Process? = null
    private val handler = Handler(Looper.getMainLooper())
    private val lines = ArrayDeque<CharSequence>(MAX_LINES + 1)
    private lateinit var tv: TextView
    private lateinit var scroll: ScrollView
    private var autoScroll = true
    private var filterLevel = 'V' // V=all, I=info+, W=warn+, E=error

    companion object {
        private const val MAX_LINES = 500
        private const val TAGS = "ZX-PAYLOAD:V ZX-IL2:V ZX-FEAT:V ZX-ANO:V ZX-ESP:V ZX-INJECT:V"
        private val TS_FMT = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

        private val COL_VERBOSE = Color.parseColor("#9E9E9E")
        private val COL_DEBUG   = Color.parseColor("#64B5F6")
        private val COL_INFO    = Color.parseColor("#E0E0E0")
        private val COL_WARN    = Color.parseColor("#FFD54F")
        private val COL_ERROR   = Color.parseColor("#EF5350")
        private val COL_FATAL   = Color.parseColor("#FF1744")
        private val COL_TS      = Color.parseColor("#616161")
        private val COL_TAG     = Color.parseColor("#AB47BC")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = buildLayout()
        setContentView(root)
        title = "ZX Console"

        startCapture()
    }

    private fun buildLayout(): android.view.View {
        val ctx = this

        val root = android.widget.LinearLayout(ctx).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0D0D0D"))
            setPadding(0, 0, 0, 0)
        }

        // ── top bar
        val bar = android.widget.LinearLayout(ctx).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
            setBackgroundColor(Color.parseColor("#1A1A1A"))
            setPadding(16, 12, 16, 12)
        }

        val tvTitle = TextView(ctx).apply {
            text = "ZX LOGCAT"
            setTextColor(Color.parseColor("#AB47BC"))
            textSize = 13f
            typeface = Typeface.MONOSPACE
            layoutParams = android.widget.LinearLayout.LayoutParams(0,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }

        val btnClear = Button(ctx).apply {
            text = "CLEAR"
            textSize = 11f
            setTextColor(Color.parseColor("#9E9E9E"))
            setBackgroundColor(Color.parseColor("#252525"))
            setPadding(20, 4, 20, 4)
            minHeight = 0
            minimumHeight = 0
            val p = android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT)
            p.marginEnd = 8
            layoutParams = p
        }

        val btnFilter = Button(ctx).apply {
            text = "LVL: V"
            textSize = 11f
            setTextColor(Color.parseColor("#9E9E9E"))
            setBackgroundColor(Color.parseColor("#252525"))
            setPadding(20, 4, 20, 4)
            minHeight = 0
            minimumHeight = 0
            val p = android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT)
            p.marginEnd = 8
            layoutParams = p
        }

        val btnScroll = Button(ctx).apply {
            text = "↓ AUTO"
            textSize = 11f
            setTextColor(Color.parseColor("#66BB6A"))
            setBackgroundColor(Color.parseColor("#252525"))
            setPadding(20, 4, 20, 4)
            minHeight = 0
            minimumHeight = 0
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT)
        }

        bar.addView(tvTitle)
        bar.addView(btnClear)
        bar.addView(btnFilter)
        bar.addView(btnScroll)
        root.addView(bar)

        // ── log area
        scroll = ScrollView(ctx).apply {
            setBackgroundColor(Color.parseColor("#0D0D0D"))
            isVerticalScrollBarEnabled = true
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        }

        tv = TextView(ctx).apply {
            typeface = Typeface.MONOSPACE
            textSize = 10.5f
            setTextColor(COL_INFO)
            setPadding(12, 8, 12, 8)
            setTextIsSelectable(true)
        }
        scroll.addView(tv)
        root.addView(scroll)

        // ── status bar
        val tvStatus = TextView(ctx).apply {
            text = "● connecting…"
            textSize = 10f
            setTextColor(Color.parseColor("#616161"))
            typeface = Typeface.MONOSPACE
            setPadding(16, 6, 16, 6)
            setBackgroundColor(Color.parseColor("#111111"))
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        root.addView(tvStatus)

        // ── listeners
        btnClear.setOnClickListener {
            lines.clear()
            tv.text = ""
            appendLine(colorLine("--- cleared ---", COL_TS))
        }

        val levels = listOf('V', 'D', 'I', 'W', 'E')
        btnFilter.setOnClickListener {
            val idx = (levels.indexOf(filterLevel) + 1) % levels.size
            filterLevel = levels[idx]
            btnFilter.text = "LVL: $filterLevel"
        }

        btnScroll.setOnClickListener {
            autoScroll = !autoScroll
            btnScroll.text = if (autoScroll) "↓ AUTO" else "PAUSED"
            btnScroll.setTextColor(if (autoScroll) Color.parseColor("#66BB6A") else COL_WARN)
            if (autoScroll) scrollBottom()
        }

        scroll.viewTreeObserver.addOnScrollChangedListener {
            val maxScroll = scroll.getChildAt(0).height - scroll.height
            if (scroll.scrollY < maxScroll - 40) {
                if (autoScroll) {
                    autoScroll = false
                    btnScroll.text = "PAUSED"
                    btnScroll.setTextColor(COL_WARN)
                }
            }
        }

        root.setTag(R.id.tv_status_sub, tvStatus)
        return root
    }

    private fun startCapture() {
        running.set(true)
        Thread {
            val cmd = "logcat -c 2>/dev/null; logcat -v threadtime $TAGS"
            var proc: Process? = null
            try {
                proc = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
                logProcess = proc
                updateStatus("● running (su)")

                val reader = BufferedReader(InputStreamReader(proc.inputStream), 8192)
                var line: String?
                while (running.get()) {
                    line = reader.readLine() ?: break
                    val parsed = parseLine(line) ?: continue
                    if (!passesFilter(parsed.level)) continue
                    val span = formatLine(parsed)
                    handler.post { appendLine(span) }
                }
            } catch (e: Exception) {
                updateStatus("✖ ${e.message}")
            } finally {
                try { proc?.destroy() } catch (_: Exception) {}
                if (running.get()) {
                    updateStatus("● process died — restarting…")
                    Thread.sleep(1500)
                    if (running.get()) startCapture()
                }
            }
        }.also { it.isDaemon = true; it.name = "zx-logcat" }.start()
    }

    private fun updateStatus(msg: String) {
        handler.post {
            try {
                val tvStatus = window.decorView
                    .findViewById<TextView>(R.id.tv_status_sub)
                tvStatus?.text = msg
            } catch (_: Exception) {}
        }
    }

    private fun appendLine(span: CharSequence) {
        if (lines.size >= MAX_LINES) lines.removeFirst()
        lines.addLast(span)
        val sb = android.text.SpannableStringBuilder()
        lines.forEach { sb.append(it); sb.append("\n") }
        tv.text = sb
        if (autoScroll) scrollBottom()
    }

    private fun scrollBottom() {
        scroll.post { scroll.fullScroll(android.view.View.FOCUS_DOWN) }
    }

    data class LogEntry(val ts: String, val pid: String, val level: Char, val tag: String, val msg: String)

    private val lineRe = Regex(
        """^(\d{2}-\d{2}\s+[\d:.]+)\s+(\d+)\s+\d+\s+([VDIWEF])\s+([\w.\-/]+)\s*:\s*(.*)$"""
    )

    private fun parseLine(raw: String): LogEntry? {
        val m = lineRe.matchEntire(raw.trim()) ?: return null
        return LogEntry(
            ts    = m.groupValues[1],
            pid   = m.groupValues[2],
            level = m.groupValues[3].firstOrNull() ?: 'V',
            tag   = m.groupValues[4],
            msg   = m.groupValues[5]
        )
    }

    private fun passesFilter(level: Char): Boolean {
        val order = "VDIWEF"
        return order.indexOf(level) >= order.indexOf(filterLevel)
    }

    private fun levelColor(level: Char) = when (level) {
        'V' -> COL_VERBOSE
        'D' -> COL_DEBUG
        'I' -> COL_INFO
        'W' -> COL_WARN
        'E' -> COL_ERROR
        'F' -> COL_FATAL
        else -> COL_INFO
    }

    private fun formatLine(e: LogEntry): CharSequence {
        val sb = android.text.SpannableStringBuilder()
        sb.append(colorSpan("${e.ts} ", COL_TS))
        sb.append(colorSpan("${e.level}/", levelColor(e.level)))
        sb.append(colorSpan("${e.tag}: ", COL_TAG))
        sb.append(colorSpan(e.msg, levelColor(e.level)))
        return sb
    }

    private fun colorLine(text: String, color: Int): CharSequence {
        val sp = SpannableString(text)
        sp.setSpan(ForegroundColorSpan(color), 0, text.length, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        return sp
    }

    private fun colorSpan(text: String, color: Int): CharSequence {
        val sp = SpannableString(text)
        sp.setSpan(ForegroundColorSpan(color), 0, text.length, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
        return sp
    }

    override fun onDestroy() {
        super.onDestroy()
        running.set(false)
        try { logProcess?.destroy() } catch (_: Exception) {}
    }
}
