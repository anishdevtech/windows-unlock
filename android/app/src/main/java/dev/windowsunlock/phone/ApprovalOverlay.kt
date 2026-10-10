package dev.windowsunlock.phone

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.animation.DecelerateInterpolator
import android.widget.LinearLayout
import android.widget.TextView

/** A push is only a hint. Review happens in MainActivity after signature verification.
 * Views use applicationContext, are removed after at most 60s, and never retain an Activity. */
@android.annotation.SuppressLint("StaticFieldLeak")
object ApprovalOverlay {
    private val handler = Handler(Looper.getMainLooper())
    private var card: View? = null
    private var manager: WindowManager? = null
    private var requestId: String? = null
    private var foreground = false
    private val expiry = Runnable { dismiss() }

    fun enabled(context: Context) = Settings.canDrawOverlays(context) && context.getSharedPreferences("approval-ui", Context.MODE_PRIVATE).getBoolean("overlay", false)
    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences("approval-ui", Context.MODE_PRIVATE).edit().putBoolean("overlay", enabled).apply()
        if (!enabled) dismiss()
    }
    fun setForeground(active: Boolean) { foreground = active; if (active) dismiss() }
    fun dismiss() {
        if (Looper.myLooper() != Looper.getMainLooper()) { handler.post { dismiss() }; return }
        handler.removeCallbacks(expiry)
        card?.let { try { manager?.removeViewImmediate(it) } catch (_: Exception) { } }
        card = null; manager = null; requestId = null
    }
    fun show(context: Context, id: String, remaining: Long) {
        val app = context.applicationContext
        handler.post {
            if (foreground || !enabled(app) || app.getSystemService(KeyguardManager::class.java).isKeyguardLocked) return@post
            if (requestId == id || remaining <= 0) return@post
            dismiss()
            val density = app.resources.displayMetrics.density
            fun dp(value: Int) = (value * density).toInt()
            val container = LinearLayout(app).apply {
                orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(18), dp(22), dp(16))
                background = GradientDrawable(GradientDrawable.Orientation.TL_BR, intArrayOf(Color.rgb(32, 60, 50), Color.rgb(18, 30, 24))).apply {
                    cornerRadius = dp(26).toFloat(); setStroke(dp(1), Color.rgb(72, 105, 86))
                }
                elevation = dp(14).toFloat()
                filterTouchesWhenObscured = true
            }
            fun label(text: String, size: Float, color: Int, bold: Boolean = false) = TextView(app).apply {
                this.text = text; textSize = size; setTextColor(color); setPadding(0, dp(4), 0, dp(4))
                if (bold) setTypeface(typeface, Typeface.BOLD)
            }
            container.addView(label("WINDOWS UNLOCK", 11f, Color.rgb(181,245,207), true))
            container.addView(label("Your laptop needs you.", 22f, Color.WHITE, true))
            container.addView(label("Tap to verify the request and authenticate.", 14f, Color.rgb(190,207,197)))
            val review = label("Review request  →", 16f, Color.rgb(181,245,207), true).apply {
                minHeight = dp(48); gravity = Gravity.CENTER_VERTICAL
                setOnClickListener {
                    dismiss()
                    try { app.startActivity(Intent(app, MainActivity::class.java).putExtra("approvalRequestId", id)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)) } catch (_: Exception) { /* Notification remains available. */ }
                }
            }
            container.addView(review)
            container.addView(label("Dismiss", 14f, Color.rgb(190,207,197)).apply { minHeight = dp(48); gravity = Gravity.CENTER_VERTICAL; setOnClickListener { dismiss() } })
            val wm = app.getSystemService(WindowManager::class.java)
            val width = minOf(dp(360), app.resources.displayMetrics.widthPixels - dp(32))
            val params = WindowManager.LayoutParams(width, WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE, PixelFormat.TRANSLUCENT).apply { gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL; y = dp(52) }
            try {
                container.alpha = 0f; container.translationY = -dp(24).toFloat()
                wm.addView(container, params); manager = wm; card = container; requestId = id
                container.animate().alpha(1f).translationY(0f).setDuration(280).setInterpolator(DecelerateInterpolator()).start()
                handler.postDelayed(expiry, remaining.coerceAtMost(60000))
            } catch (_: Exception) { dismiss() }
        }
    }
}
