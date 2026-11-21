"""Заглушки Android SDK, libv2ray, zxing и JSch — только чтобы проверить, что код платформы компилируется
(сигнатуры как в настоящих библиотеках). Запуск: python3 make_stubs.py <папка>."""
import os, sys, textwrap

out = sys.argv[1]
S = {}

S["android.annotation.SuppressLint"] = "public @interface SuppressLint { String[] value(); }"
S["android.Manifest"] = """public final class Manifest { public static final class permission {
  public static final String POST_NOTIFICATIONS = "a", NEARBY_WIFI_DEVICES = "b", ACCESS_FINE_LOCATION = "c"; } }"""
S["android.content.Context"] = """public abstract class Context {
  public static final String CONNECTIVITY_SERVICE = "c", WIFI_SERVICE = "w", CLIPBOARD_SERVICE = "cl", NOTIFICATION_SERVICE = "n",
      POWER_SERVICE = "p", KEYGUARD_SERVICE = "k";
  public abstract Context getApplicationContext();
  public abstract java.io.File getFilesDir();
  public abstract ContentResolver getContentResolver();
  public abstract Object getSystemService(String name);
  public abstract String getPackageName();
  public abstract android.content.pm.PackageManager getPackageManager();
  public abstract ComponentName startForegroundService(Intent i);
  public abstract ComponentName startService(Intent i);
  public abstract void startActivity(Intent i);
  public abstract int checkSelfPermission(String p);
}"""
S["android.content.ContextWrapper"] = """public class ContextWrapper extends Context {
  public Context getApplicationContext() { return null; }
  public java.io.File getFilesDir() { return null; }
  public ContentResolver getContentResolver() { return null; }
  public Object getSystemService(String name) { return null; }
  public String getPackageName() { return null; }
  public android.content.pm.PackageManager getPackageManager() { return null; }
  public ComponentName startForegroundService(Intent i) { return null; }
  public ComponentName startService(Intent i) { return null; }
  public void startActivity(Intent i) {}
  public int checkSelfPermission(String p) { return 0; }
}"""
S["android.content.ContentResolver"] = """public abstract class ContentResolver {
  public final java.io.InputStream openInputStream(android.net.Uri u) throws java.io.FileNotFoundException { return null; }
  public final java.io.OutputStream openOutputStream(android.net.Uri u) throws java.io.FileNotFoundException { return null; }
}"""
S["android.content.ComponentName"] = "public final class ComponentName { public ComponentName(Context c, Class<?> cls) {} }"
S["android.content.ActivityNotFoundException"] = "public class ActivityNotFoundException extends RuntimeException {}"
S["android.content.ClipData"] = """public class ClipData {
  public static ClipData newPlainText(CharSequence label, CharSequence text) { return null; }
  public int getItemCount() { return 0; }
  public Item getItemAt(int i) { return null; }
  public static class Item { public CharSequence getText() { return null; } }
}"""
S["android.content.ClipboardManager"] = """public class ClipboardManager {
  public void setPrimaryClip(ClipData c) {}
  public ClipData getPrimaryClip() { return null; }
}"""
S["android.content.Intent"] = """public class Intent {
  public static final String ACTION_SEND = "s", ACTION_VIEW = "v", ACTION_MAIN = "m", EXTRA_TEXT = "t", EXTRA_TITLE = "ti",
    ACTION_OPEN_DOCUMENT = "o", ACTION_CREATE_DOCUMENT = "c", CATEGORY_OPENABLE = "co", CATEGORY_LAUNCHER = "l",
    EXTRA_STREAM = "st", EXTRA_SUBJECT = "su";
  public static final int FLAG_ACTIVITY_NEW_TASK = 1, FLAG_ACTIVITY_SINGLE_TOP = 2, FLAG_GRANT_READ_URI_PERMISSION = 4;
  public Intent() {}
  public Intent(String action) {}
  public Intent(String action, android.net.Uri uri) {}
  public Intent(Context c, Class<?> cls) {}
  public Intent setAction(String a) { return this; }
  public Intent setDataAndType(android.net.Uri u, String t) { return this; }
  public String getAction() { return null; }
  public String getStringExtra(String n) { return null; }
  public android.net.Uri getData() { return null; }
  public boolean getBooleanExtra(String n, boolean d) { return d; }
  public void removeExtra(String n) {}
  public Intent putExtra(String n, boolean v) { return this; }
  public Intent putExtra(String n, String v) { return this; }
  public Intent putExtra(String n, android.os.Parcelable v) { return this; }
  public Intent addFlags(int f) { return this; }
  public Intent setFlags(int f) { return this; }
  public Intent addCategory(String c) { return this; }
  public Intent setType(String t) { return this; }
  public Intent setClassName(String p, String c) { return this; }
  public Intent setPackage(String p) { return this; }
  public static Intent createChooser(Intent target, CharSequence title) { return null; }
}"""
S["android.content.pm.PackageManager"] = """public abstract class PackageManager {
  public static final int PERMISSION_GRANTED = 0;
  public static class NameNotFoundException extends android.util.AndroidException {}
  public abstract java.util.List<ResolveInfo> queryIntentActivities(android.content.Intent i, int flags);
  public boolean canRequestPackageInstalls() { return true; }
  public android.content.Intent getLaunchIntentForPackage(String packageName) { return null; }
}"""
S["android.util.AndroidException"] = "public class AndroidException extends Exception {}"
S["android.content.pm.ResolveInfo"] = """public class ResolveInfo {
  public ActivityInfo activityInfo;
  public CharSequence loadLabel(PackageManager pm) { return null; }
}"""
S["android.content.pm.ActivityInfo"] = "public class ActivityInfo { public String packageName; }"
S["android.content.pm.ServiceInfo"] = "public class ServiceInfo { public static final int FOREGROUND_SERVICE_TYPE_SPECIAL_USE = 0x40000000; }"
S["android.app.Application"] = "public class Application extends android.content.ContextWrapper { public void onCreate() {} }"
S["android.app.Service"] = """public abstract class Service extends android.content.ContextWrapper {
  public static final int START_STICKY = 1, START_NOT_STICKY = 2, STOP_FOREGROUND_REMOVE = 1;
  public void onCreate() {}
  public int onStartCommand(android.content.Intent i, int flags, int id) { return 0; }
  public void onDestroy() {}
  public final void startForeground(int id, Notification n) {}
  public final void startForeground(int id, Notification n, int type) {}
  public final void stopForeground(int flags) {}
  public final void stopForeground(boolean remove) {}
  public final void stopSelf() {}
}"""
S["android.app.Activity"] = """public class Activity extends android.content.ContextWrapper {
  public static final int RESULT_OK = -1;
  protected void onCreate(android.os.Bundle b) {}
  protected void onNewIntent(android.content.Intent i) {}
  protected void onDestroy() {}
  protected void onStart() {}
  protected void onStop() {}
  public void finish() {}
  protected void onActivityResult(int req, int res, android.content.Intent data) {}
  public void onRequestPermissionsResult(int req, String[] perms, int[] results) {}
  public void onBackPressed() {}
  public android.view.Window getWindow() { return null; }
  public void setContentView(android.view.View v) {}
  public android.content.Intent getIntent() { return null; }
  public void setIntent(android.content.Intent i) {}
  public void startActivityForResult(android.content.Intent i, int req) {}
  public final void runOnUiThread(Runnable r) {}
  public final void requestPermissions(String[] p, int req) {}
  public boolean moveTaskToBack(boolean nonRoot) { return true; }
}"""
S["android.app.Notification"] = """public class Notification {
  public static class Builder {
    public Builder(android.content.Context c, String channel) {}
    public Builder(android.content.Context c) {}
    public Builder setSmallIcon(int icon) { return this; }
    public Builder setContentTitle(CharSequence t) { return this; }
    public Builder setContentText(CharSequence t) { return this; }
    public Builder setContentIntent(PendingIntent p) { return this; }
    public Builder setOngoing(boolean b) { return this; }
    public Builder setShowWhen(boolean b) { return this; }
    public Builder setOnlyAlertOnce(boolean b) { return this; }
    public Builder addAction(Action a) { return this; }
    public Builder setStyle(Style s) { return this; }
    public Builder setAutoCancel(boolean b) { return this; }
    public Notification build() { return null; }
  }
  public abstract static class Style {}
  public static class BigTextStyle extends Style {
    public BigTextStyle bigText(CharSequence t) { return this; }
  }
  public static class Action {
    public static final class Builder {
      public Builder(android.graphics.drawable.Icon icon, CharSequence title, PendingIntent intent) {}
      public Action build() { return null; }
    }
  }
}"""
S["android.app.NotificationChannel"] = """public final class NotificationChannel {
  public NotificationChannel(String id, CharSequence name, int importance) {}
  public void setShowBadge(boolean b) {}
}"""
S["android.app.NotificationManager"] = """public class NotificationManager {
  public static final int IMPORTANCE_LOW = 2, IMPORTANCE_DEFAULT = 3;
  public boolean areNotificationsEnabled() { return true; }
  public void createNotificationChannel(NotificationChannel c) {}
  public void notify(int id, Notification n) {}
}"""
S["android.app.PendingIntent"] = """public final class PendingIntent {
  public static final int FLAG_IMMUTABLE = 1 << 26, FLAG_UPDATE_CURRENT = 1 << 27;
  public static PendingIntent getActivity(android.content.Context c, int code, android.content.Intent i, int flags) { return null; }
  public static PendingIntent getService(android.content.Context c, int code, android.content.Intent i, int flags) { return null; }
  public static PendingIntent getBroadcast(android.content.Context c, int code, android.content.Intent i, int flags) { return null; }
}"""
S["android.graphics.Bitmap"] = """public final class Bitmap {
  public enum Config { ARGB_8888 }
  public enum CompressFormat { PNG }
  public static Bitmap createBitmap(int[] colors, int width, int height, Config config) { return null; }
  public boolean compress(CompressFormat f, int q, java.io.OutputStream out) { return true; }
  public void recycle() {}
}"""
S["android.graphics.Color"] = """public class Color {
  public static final int TRANSPARENT = 0;
  public static int parseColor(String s) { return 0; }
}"""
S["android.graphics.Insets"] = "public final class Insets { public final int left = 0, top = 0, right = 0, bottom = 0; }"
S["android.graphics.drawable.Icon"] = """public final class Icon {
  public static Icon createWithResource(android.content.Context c, int res) { return null; }
}"""
S["android.net.Uri"] = """public abstract class Uri implements android.os.Parcelable {
  public abstract String getScheme();
  public abstract String getLastPathSegment();
  public static String encode(String s) { return s; }
  public abstract String getPath();
  public static Uri parse(String s) { return null; }
}"""
S["android.net.Network"] = "public class Network {}"
S["android.net.LinkProperties"] = "public final class LinkProperties { public String getInterfaceName() { return null; } }"
S["android.net.NetworkCapabilities"] = """public final class NetworkCapabilities {
  public static final int TRANSPORT_VPN = 4, TRANSPORT_WIFI = 1, TRANSPORT_CELLULAR = 0, NET_CAPABILITY_INTERNET = 12,
      NET_CAPABILITY_CAPTIVE_PORTAL = 17;
  public boolean hasTransport(int t) { return false; }
  public boolean hasCapability(int c) { return false; }
  public TransportInfo getTransportInfo() { return null; }
}"""
S["android.net.TransportInfo"] = "public interface TransportInfo {}"
S["android.net.wifi.WifiInfo"] = """public class WifiInfo implements android.net.TransportInfo {
  public int getCurrentSecurityType() { return -1; }
}"""
S["android.net.ConnectivityManager"] = """public class ConnectivityManager {
  public static class NetworkCallback {
    public void onAvailable(Network network) {}
    public void onLost(Network network) {}
  }
  public void registerDefaultNetworkCallback(NetworkCallback cb) {}
  public void unregisterNetworkCallback(NetworkCallback cb) {}
  public static final int RESTRICT_BACKGROUND_STATUS_ENABLED = 3;
  public int getRestrictBackgroundStatus() { return 1; }
  public NetworkCapabilities getNetworkCapabilities(Network n) { return null; }
  public Network getActiveNetwork() { return null; }
  public Network[] getAllNetworks() { return new Network[0]; }
  public LinkProperties getLinkProperties(Network n) { return null; }
}"""
S["android.net.VpnService"] = """public class VpnService extends android.app.Service {
  public static final String SERVICE_INTERFACE = "android.net.VpnService";
  public static android.content.Intent prepare(android.content.Context c) { return null; }
  public void onRevoke() {}
  public class Builder {
    public Builder() {}
    public Builder setSession(String s) { return this; }
    public Builder setMtu(int m) { return this; }
    public Builder addAddress(String a, int p) { return this; }
    public Builder addRoute(String a, int p) { return this; }
    public Builder addDnsServer(String a) { return this; }
    public Builder addDisallowedApplication(String pkg) throws android.content.pm.PackageManager.NameNotFoundException { return this; }
    public Builder setMetered(boolean m) { return this; }
    public Builder setConfigureIntent(android.app.PendingIntent p) { return this; }
    public android.os.ParcelFileDescriptor establish() { return null; }
  }
}"""
S["android.net.wifi.SoftApConfiguration"] = """public final class SoftApConfiguration {
  @Deprecated public String getSsid() { return null; }
  public String getPassphrase() { return null; }
}"""
S["android.net.wifi.WifiConfiguration"] = "@Deprecated public class WifiConfiguration { public String SSID; public String preSharedKey; }"
S["android.net.wifi.WifiManager"] = """public class WifiManager {
  public void startLocalOnlyHotspot(LocalOnlyHotspotCallback cb, android.os.Handler h) {}
  public static class LocalOnlyHotspotCallback {
    public static final int ERROR_NO_CHANNEL = 1, ERROR_GENERIC = 2, ERROR_INCOMPATIBLE_MODE = 3, ERROR_TETHERING_DISALLOWED = 4;
    public void onStarted(LocalOnlyHotspotReservation r) {}
    public void onStopped() {}
    public void onFailed(int reason) {}
  }
  public class LocalOnlyHotspotReservation implements AutoCloseable {
    public SoftApConfiguration getSoftApConfiguration() { return null; }
    @Deprecated public WifiConfiguration getWifiConfiguration() { return null; }
    public void close() {}
  }
}"""
S["android.os.Build"] = """public class Build {
  public static final String MANUFACTURER = "m", MODEL = "x";
  public static final String[] SUPPORTED_ABIS = {"arm64-v8a"};
  public static class VERSION { public static final int SDK_INT = 35; public static final String RELEASE = "15"; }
}"""
S["android.os.PowerManager"] = """public final class PowerManager {
  public boolean isIgnoringBatteryOptimizations(String pkg) { return false; }
}"""
S["android.os.StatFs"] = """public class StatFs {
  public StatFs(String path) {}
  public long getAvailableBytes() { return 0; }
}"""
S["android.os.Bundle"] = "public final class Bundle {}"
S["android.os.Looper"] = "public final class Looper { public static Looper getMainLooper() { return null; } }"
S["android.os.Handler"] = "public class Handler { public Handler(Looper l) {} }"
S["android.os.ParcelFileDescriptor"] = """public class ParcelFileDescriptor implements java.io.Closeable {
  public static final int MODE_READ_ONLY = 0x10000000;
  public static ParcelFileDescriptor open(java.io.File f, int mode) throws java.io.FileNotFoundException { return null; }
  public int getFd() { return 0; }
  public void close() throws java.io.IOException {}
}"""
S["android.provider.Settings"] = """public final class Settings {
  public static final String ACTION_WIRELESS_SETTINGS = "w", ACTION_VPN_SETTINGS = "v",
      ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS = "rb", ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS = "ib",
      ACTION_APP_NOTIFICATION_SETTINGS = "an", EXTRA_APP_PACKAGE = "ep", ACTION_APPLICATION_DETAILS_SETTINGS = "ad",
      ACTION_IGNORE_BACKGROUND_DATA_RESTRICTIONS_SETTINGS = "bd";
  public static final class Secure {
    public static final String ANDROID_ID = "android_id";
    public static String getString(android.content.ContentResolver r, String name) { return null; }
  }
  public static final class Global {
    public static String getString(android.content.ContentResolver r, String name) { return null; }
  }
}"""
S["android.service.quicksettings.Tile"] = """public final class Tile {
  public static final int STATE_INACTIVE = 1, STATE_ACTIVE = 2;
  public void setState(int s) {}
  public void setLabel(CharSequence l) {}
  public void updateTile() {}
}"""
S["android.service.quicksettings.TileService"] = """public class TileService extends android.app.Service {
  public static final void requestListeningState(android.content.Context c, android.content.ComponentName n) {}
  public final Tile getQsTile() { return null; }
  public void onStartListening() {}
  public void onClick() {}
  @Deprecated public final void startActivityAndCollapse(android.content.Intent i) {}
  public final void startActivityAndCollapse(android.app.PendingIntent p) {}
}"""
S["android.view.View"] = """public class View {
  public static final int SYSTEM_UI_FLAG_LAYOUT_STABLE = 256, SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN = 1024,
    SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION = 512, SYSTEM_UI_FLAG_LIGHT_STATUS_BAR = 8192, SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR = 16;
  public View(android.content.Context c) {}
  @Deprecated public void setSystemUiVisibility(int v) {}
  @Deprecated public int getSystemUiVisibility() { return 0; }
  public void setOnApplyWindowInsetsListener(OnApplyWindowInsetsListener l) {}
  public void setPadding(int l, int t, int r, int b) {}
  public void setBackgroundColor(int c) {}
  public static final int VISIBLE = 0, INVISIBLE = 4, GONE = 8;
  public void setVisibility(int v) {}
  public interface OnApplyWindowInsetsListener { WindowInsets onApplyWindowInsets(View v, WindowInsets insets); }
}"""
S["android.view.ViewGroup"] = """public abstract class ViewGroup extends View {
  public ViewGroup(android.content.Context c) { super(c); }
  public void addView(View v, LayoutParams p) {}
  public static class LayoutParams { public static final int MATCH_PARENT = -1; public LayoutParams(int w, int h) {} }
}"""
S["android.view.Window"] = """public abstract class Window {
  public void setDecorFitsSystemWindows(boolean b) {}
  public abstract View getDecorView();
  @Deprecated public abstract void setStatusBarColor(int c);
  @Deprecated public abstract void setNavigationBarColor(int c);
  public WindowInsetsController getInsetsController() { return null; }
}"""
S["android.view.WindowInsets"] = """public final class WindowInsets {
  public static final WindowInsets CONSUMED = null;
  public android.graphics.Insets getInsets(int typeMask) { return null; }
  @Deprecated public int getSystemWindowInsetLeft() { return 0; }
  @Deprecated public int getSystemWindowInsetTop() { return 0; }
  @Deprecated public int getSystemWindowInsetRight() { return 0; }
  @Deprecated public int getSystemWindowInsetBottom() { return 0; }
  @Deprecated public WindowInsets consumeSystemWindowInsets() { return this; }
  public static final class Type {
    public static int systemBars() { return 1; }
    public static int ime() { return 2; }
    public static int displayCutout() { return 4; }
  }
}"""
S["android.view.WindowInsetsController"] = """public interface WindowInsetsController {
  int APPEARANCE_LIGHT_STATUS_BARS = 8, APPEARANCE_LIGHT_NAVIGATION_BARS = 16;
  void setSystemBarsAppearance(int appearance, int mask);
}"""
S["android.widget.FrameLayout"] = """public class FrameLayout extends android.view.ViewGroup {
  public FrameLayout(android.content.Context c) { super(c); }
  public static class LayoutParams extends android.view.ViewGroup.LayoutParams { public LayoutParams(int w, int h) { super(w, h); } }
}"""
S["android.webkit.JavascriptInterface"] = """@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@java.lang.annotation.Target(java.lang.annotation.ElementType.METHOD)
public @interface JavascriptInterface {}"""
S["android.webkit.ValueCallback"] = "public interface ValueCallback<T> { void onReceiveValue(T value); }"
S["android.webkit.WebResourceRequest"] = "public interface WebResourceRequest { android.net.Uri getUrl(); }"
S["android.webkit.WebSettings"] = """public abstract class WebSettings {
  public static final int MIXED_CONTENT_NEVER_ALLOW = 1;
  public abstract void setJavaScriptEnabled(boolean b);
  public abstract void setDomStorageEnabled(boolean b);
  public abstract void setAllowContentAccess(boolean b);
  public abstract void setAllowFileAccess(boolean b);
  public abstract void setMixedContentMode(int m);
  public abstract void setTextZoom(int z);
}"""
S["android.webkit.WebViewClient"] = """public class WebViewClient {
  public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) { return false; }
  public void onPageFinished(WebView v, String url) {}
}"""
S["android.webkit.WebView"] = """public class WebView extends android.view.View {
  public WebView(android.content.Context c) { super(c); }
  public WebSettings getSettings() { return null; }
  public void setWebViewClient(WebViewClient c) {}
  public void addJavascriptInterface(Object o, String name) {}
  public void removeJavascriptInterface(String name) {}
  public void loadUrl(String url) {}
  public void evaluateJavascript(String script, ValueCallback<String> cb) {}
  public void destroy() {}
}"""
# libv2ray (gomobile: Go int → Java long, int32 → int, error → Exception)
S["libv2ray.CoreCallbackHandler"] = "public interface CoreCallbackHandler { long onEmitStatus(long p0, String p1); long shutdown(); long startup(); }"
S["libv2ray.CoreController"] = """public final class CoreController {
  public native boolean getIsRunning();
  public native long measureDelay(String url) throws Exception;
  public native String queryAllOutboundTrafficStats();
  public native void startLoop(String configContent, int tunFd) throws Exception;
  public native void stopLoop() throws Exception;
}"""
S["libv2ray.Libv2ray"] = """public abstract class Libv2ray {
  public static native String checkVersionX();
  public static native void initCoreEnv(String envPath, String key);
  public static native long measureOutboundDelay(String configureFileContent, String url) throws Exception;
  public static native CoreController newCoreController(CoreCallbackHandler s);
}"""
# zxing
S["com.google.zxing.BarcodeFormat"] = "public enum BarcodeFormat { QR_CODE }"
S["com.google.zxing.EncodeHintType"] = "public enum EncodeHintType { CHARACTER_SET, ERROR_CORRECTION, MARGIN }"
S["com.google.zxing.WriterException"] = "public final class WriterException extends Exception {}"
S["com.google.zxing.common.BitMatrix"] = """public final class BitMatrix {
  public boolean get(int x, int y) { return false; }
  public int getWidth() { return 0; }
  public int getHeight() { return 0; }
}"""
S["com.google.zxing.qrcode.QRCodeWriter"] = """public final class QRCodeWriter {
  public com.google.zxing.common.BitMatrix encode(String contents, com.google.zxing.BarcodeFormat format, int width, int height,
      java.util.Map<com.google.zxing.EncodeHintType, ?> hints) throws com.google.zxing.WriterException { return null; }
}"""
S["com.google.zxing.qrcode.decoder.ErrorCorrectionLevel"] = "public enum ErrorCorrectionLevel { L, M, Q, H }"
S["com.google.zxing.integration.android.IntentResult"] = "public final class IntentResult { public String getContents() { return null; } }"
S["com.google.zxing.integration.android.IntentIntegrator"] = """public class IntentIntegrator {
  public static final int REQUEST_CODE = 0x0000c0de;
  public static final String QR_CODE = "QR_CODE";
  public IntentIntegrator(android.app.Activity a) {}
  public final IntentIntegrator setDesiredBarcodeFormats(String... formats) { return this; }
  public final IntentIntegrator setPrompt(String p) { return this; }
  public IntentIntegrator setBeepEnabled(boolean b) { return this; }
  public IntentIntegrator setOrientationLocked(boolean b) { return this; }
  public final void initiateScan() {}
  public static IntentResult parseActivityResult(int requestCode, int resultCode, android.content.Intent intent) { return null; }
}"""
# JSch
S["com.jcraft.jsch.JSchException"] = "public class JSchException extends Exception {}"
S["com.jcraft.jsch.Channel"] = """public abstract class Channel {
  public java.io.InputStream getInputStream() throws java.io.IOException { return null; }
  public java.io.OutputStream getOutputStream() throws java.io.IOException { return null; }
  public void connect(int timeout) throws JSchException {}
  public void disconnect() {}
}"""
S["com.jcraft.jsch.ChannelExec"] = "public class ChannelExec extends Channel { public void setCommand(String c) {} }"
S["com.jcraft.jsch.Session"] = """public class Session {
  public void setPassword(String p) {}
  public void setConfig(java.util.Properties p) {}
  public void setServerAliveInterval(int ms) throws JSchException {}
  public void connect(int timeout) throws JSchException {}
  public boolean isConnected() { return false; }
  public void disconnect() {}
  public Channel openChannel(String type) throws JSchException { return null; }
}"""
S["com.jcraft.jsch.JSch"] = "public class JSch { public Session getSession(String user, String host, int port) throws JSchException { return null; } }"
S["android.os.Parcelable"] = "public interface Parcelable {}"
S["android.net.TrafficStats"] = """public class TrafficStats {
  public static long getUidRxBytes(int uid) { return 0; }
  public static long getUidTxBytes(int uid) { return 0; }
}"""
S["android.os.Process"] = "public class Process { public static final int myUid() { return 0; } }"
S["android.content.ContentValues"] = "public final class ContentValues {}"
S["android.database.Cursor"] = "public interface Cursor {}"
S["android.database.MatrixCursor"] = """public class MatrixCursor implements Cursor {
  public MatrixCursor(String[] columnNames, int initialCapacity) {}
  public void addRow(Object[] columnValues) {}
}"""
S["android.provider.OpenableColumns"] = """public interface OpenableColumns {
  String DISPLAY_NAME = "_display_name", SIZE = "_size";
}"""
S["android.content.ContentProvider"] = """public abstract class ContentProvider {
  public final Context getContext() { return null; }
  public abstract boolean onCreate();
  public abstract String getType(android.net.Uri uri);
  public android.os.ParcelFileDescriptor openFile(android.net.Uri uri, String mode) throws java.io.FileNotFoundException { return null; }
  public abstract android.database.Cursor query(android.net.Uri uri, String[] projection, String selection, String[] selectionArgs,
      String sortOrder);
  public abstract android.net.Uri insert(android.net.Uri uri, ContentValues values);
  public abstract int delete(android.net.Uri uri, String selection, String[] selectionArgs);
  public abstract int update(android.net.Uri uri, ContentValues values, String selection, String[] selectionArgs);
}"""
# сгенерированное сборкой
S["com.pultvpn.app.BuildConfig"] = 'public final class BuildConfig { public static final String VERSION_NAME = "0.9.0"; }'
S["com.pultvpn.app.R"] = """public final class R {
  public static final class drawable { public static final int ic_stat = 1; }
  public static final class layout { public static final int widget = 2; }
  public static final class id { public static final int widget_root = 3, widget_icon = 4, widget_title = 5, widget_state = 6; }
}"""
S["android.util.Base64"] = """public class Base64 {
  public static final int NO_WRAP = 2;
  public static String encodeToString(byte[] b, int f) { return java.util.Base64.getEncoder().encodeToString(b); }
  public static byte[] decode(String s, int f) { return java.util.Base64.getDecoder().decode(s); }
}"""
S["android.security.keystore.KeyProperties"] = """public final class KeyProperties {
  public static final String KEY_ALGORITHM_AES = "AES", BLOCK_MODE_GCM = "GCM", ENCRYPTION_PADDING_NONE = "NoPadding";
  public static final int PURPOSE_ENCRYPT = 1, PURPOSE_DECRYPT = 2;
}"""
S["android.security.keystore.KeyGenParameterSpec"] = """public final class KeyGenParameterSpec implements java.security.spec.AlgorithmParameterSpec {
  public static final class Builder {
    public Builder(String alias, int purposes) {}
    public Builder setBlockModes(String... m) { return this; }
    public Builder setEncryptionPaddings(String... p) { return this; }
    public Builder setKeySize(int n) { return this; }
    public KeyGenParameterSpec build() { return null; }
  }
}"""
S["android.app.KeyguardManager"] = """public class KeyguardManager {
  public boolean isDeviceSecure() { return true; }
  public android.content.Intent createConfirmDeviceCredentialIntent(CharSequence t, CharSequence d) { return null; }
}"""
S["android.content.BroadcastReceiver"] = """public abstract class BroadcastReceiver {
  public abstract void onReceive(Context c, Intent i);
}"""
S["android.appwidget.AppWidgetProvider"] = """public class AppWidgetProvider extends android.content.BroadcastReceiver {
  public void onReceive(android.content.Context c, android.content.Intent i) {}
  public void onUpdate(android.content.Context c, AppWidgetManager m, int[] ids) {}
}"""
S["android.appwidget.AppWidgetManager"] = """public class AppWidgetManager {
  public static AppWidgetManager getInstance(android.content.Context c) { return null; }
  public int[] getAppWidgetIds(android.content.ComponentName n) { return null; }
  public void updateAppWidget(int id, android.widget.RemoteViews v) {}
}"""
S["android.widget.RemoteViews"] = """public class RemoteViews {
  public RemoteViews(String pkg, int layout) {}
  public void setTextViewText(int id, CharSequence t) {}
  public void setInt(int id, String method, int v) {}
  public void setOnClickPendingIntent(int id, android.app.PendingIntent p) {}
}"""

# одна и та же заглушка дважды — вторая молча затёрла бы первую
import re as _re
_keys = _re.findall(r'^S\["([^"]+)"\]', open(__file__, encoding="utf-8").read(), _re.M)
_dup = sorted({k for k in _keys if _keys.count(k) > 1})
if _dup:
    sys.exit("повторяются заглушки: " + ", ".join(_dup))
for name, body in S.items():
    pkg, cls = name.rsplit(".", 1)
    d = os.path.join(out, *pkg.split("."))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, cls + ".java"), "w", encoding="utf-8") as f:
        f.write(f"package {pkg};\n\n{textwrap.dedent(body)}\n")
print(len(S), "stubs")
