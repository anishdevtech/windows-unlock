package dev.windowsunlock.phone

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Composable
fun UnlockTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = darkColorScheme(
        primary = Color(0xFFB5F5CF), onPrimary = Color(0xFF103B2B),
        primaryContainer = Color(0xFF203C32), onPrimaryContainer = Color(0xFFE0F7EA),
        secondary = Color(0xFFA1B8AF), background = Color(0xFF0C1210),
        surface = Color(0xFF171F1B), surfaceVariant = Color(0xFF25322B),
        onSurface = Color(0xFFEDF3EE), onSurfaceVariant = Color(0xFFA8B8AE), outline = Color(0xFF4C6255)
    ), shapes = Shapes(small = androidx.compose.foundation.shape.RoundedCornerShape(12.dp), medium = androidx.compose.foundation.shape.RoundedCornerShape(20.dp), large = androidx.compose.foundation.shape.RoundedCornerShape(28.dp)), content = content)
}
