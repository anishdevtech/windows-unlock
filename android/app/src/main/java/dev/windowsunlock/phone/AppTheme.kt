package dev.windowsunlock.phone

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

@Composable
fun UnlockTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = darkColorScheme(
        primary = Color(0xFF9FC4FF), onPrimary = Color(0xFF002E69),
        primaryContainer = Color(0xFF124986), onPrimaryContainer = Color(0xFFD7E7FF),
        secondary = Color(0xFF83D9C0), background = Color(0xFF0C1422),
        surface = Color(0xFF111D2E), surfaceVariant = Color(0xFF213148),
        onSurface = Color(0xFFE2EBFA), outline = Color(0xFF52637B)
    ), content = content)
}
