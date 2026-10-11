package dev.windowsunlock.phone

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.*

@Composable fun UpdateSettings() {
    val context=LocalContext.current;val scope=rememberCoroutineScope()
    var automatic by remember { mutableStateOf(AppUpdates.automatic(context)) }
    var message by remember { mutableStateOf("Installed ${BuildConfig.VERSION_NAME}") }
    var ready by remember { mutableStateOf(AppUpdates.ready(context)) }
    var release by remember { mutableStateOf<AppRelease?>(null) }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(Unit){while(isActive){ready=AppUpdates.ready(context);delay(1500)}}
    Column(verticalArrangement=Arrangement.spacedBy(8.dp)) {
        Text("App updates",style=MaterialTheme.typography.titleLarge)
        Text(message)
        Row(Modifier.fillMaxWidth()){Text("Check & download automatically on Wi-Fi",Modifier.weight(1f));Switch(checked=automatic,onCheckedChange={automatic=it;AppUpdates.automatic(context,it)})}
        Text("Checks daily and when opened. Downloads must match this app's signing certificate. Android asks you to confirm installation.",style=MaterialTheme.typography.bodySmall)
        OutlinedButton(enabled=!busy,onClick={busy=true;scope.launch{try{val found=withContext(Dispatchers.IO){AppUpdates.check()};release=found.takeIf{it.versionCode>BuildConfig.VERSION_CODE};message=if(release==null)"You're up to date · ${BuildConfig.VERSION_NAME}" else "${found.versionName} available"}catch(_:Exception){message="Couldn't check updates. Check your connection and retry."}finally{busy=false}}}){Text("Check for updates")}
        if(release!=null&&ready==null)Button(enabled=!busy,onClick={busy=true;scope.launch{try{withContext(Dispatchers.IO){AppUpdates.download(context,release!!)};ready=AppUpdates.ready(context);message="Verified update ready"}catch(_:Exception){message="Download failed or update verification rejected it. Retry later."}finally{busy=false}}}){Text("Download ${release?.versionName}")}
        if(ready!=null)Button(enabled=!busy,onClick={busy=true;scope.launch{try{val intent=withContext(Dispatchers.IO){AppUpdates.installIntent(context)};context.startActivity(intent);message="Allow installation if asked, then tap Install again."}catch(_:Exception){message="Update unavailable or verification failed. Download it again."}finally{busy=false}}}){Text("Install $ready")}
        if(busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        HorizontalDivider()
    }
}
