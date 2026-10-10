plugins { id("com.android.application"); id("org.jetbrains.kotlin.plugin.compose") }
if (file("google-services.json").exists()) apply(plugin = "com.google.gms.google-services")
dependencyLocking { lockAllConfigurations() }
android {
    namespace = "dev.windowsunlock.phone"
    compileSdk = 36
    defaultConfig { applicationId = "dev.windowsunlock.phone"; minSdk = 30; targetSdk = 36; versionCode = 7; versionName = "0.6.1" }
    buildFeatures { compose = true; buildConfig = true }
    buildTypes {
        debug { buildConfigField("boolean", "ALLOW_SOFTWARE_KEYS", providers.gradleProperty("phoneunlock.allowSoftwareKeys").orElse("false").get()) }
        release { isMinifyEnabled = false; buildConfigField("boolean", "ALLOW_SOFTWARE_KEYS", "false") }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
}
dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.10.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.nimbusds:nimbus-jose-jwt:10.5")
    implementation(platform("com.google.firebase:firebase-bom:34.4.0"))
    implementation("com.google.firebase:firebase-messaging")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    implementation("androidx.work:work-runtime-ktx:2.10.4")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}

tasks.withType<Test>().configureEach {
    systemProperty("phoneunlock.fixtureOutput", rootProject.projectDir.resolve("../.runtime/android-interop.json").absolutePath)
}
