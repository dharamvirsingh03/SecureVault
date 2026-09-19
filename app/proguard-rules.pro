# Strip every log call from release builds. The app should not be writing secrets to logcat in the
# first place, and this removes the possibility that a stray debug line ever does.
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}

# Argon2Kt loads native code by name.
-keep class com.lambdapioneer.argon2kt.** { *; }

# Room generated code.
-keep class * extends androidx.room.RoomDatabase { <init>(); }
-dontwarn androidx.room.paging.**

# Autofill service is instantiated by the platform.
-keep class app.securevault.feature.autofill.SecureVaultAutofillService { *; }

# Keep crypto classes readable in stack traces without exposing field names.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
