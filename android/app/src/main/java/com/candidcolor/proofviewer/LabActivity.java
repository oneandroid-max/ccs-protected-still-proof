package com.candidcolor.proofviewer;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Display;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * The Android test platform: every variable in one place, measured on this phone.
 *
 * Variables: the capture refusal (the secure window flag) on or off, switched live; the content as the
 * native photo or as any page of the proof site loaded inside the app's own web view (the traceable
 * page, the decoy frame, above white, the bench, the door, or any address typed in). A page shown
 * inside this app under the secure flag is a web link whose capture the phone refuses: the web page
 * unchanged, the refusal from the app around it. Every line of the readout is measured here.
 */
public final class LabActivity extends Activity {
    static final String SITE = "https://oneandroid-max.github.io/ccs-protected-still-proof/";
    private WebView web;
    private ImageView photoView;
    private TextView readout, status;
    private EditText keyField, pinField, urlField;
    private Switch secureSwitch;
    private String content = "nothing", pinState = "-", markIdText = "-";
    private int captureAttempts = 0;
    private Object captureCallback;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        buildUi();
        String key = getIntent().getStringExtra("key"), pin = getIntent().getStringExtra("pin");
        if (key != null) keyField.setText(key);
        if (pin != null) pinField.setText(pin);
        refreshReadout();
    }

    @Override protected void onStart() { super.onStart(); if (Build.VERSION.SDK_INT >= 34) registerCapture(); }
    @Override protected void onStop() { if (Build.VERSION.SDK_INT >= 34) unregisterCapture(); super.onStop(); }
    @Override protected void onDestroy() { if (web != null) web.destroy(); super.onDestroy(); }
    private void registerCapture() { Activity.ScreenCaptureCallback cb = () -> { captureAttempts++; refreshReadout(); }; captureCallback = cb; registerScreenCaptureCallback(getMainExecutor(), cb); }
    private void unregisterCapture() { if (captureCallback != null) { unregisterScreenCaptureCallback((Activity.ScreenCaptureCallback) captureCallback); captureCallback = null; } }

    private boolean windowIsSecure() { return (getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0; }
    private void setSecure(boolean on) {
        if (on) getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE); else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
        status.setText(on ? "Capture refusal ON: a screenshot should come out black or be refused." : "Capture refusal OFF: a screenshot shows the screen as it is.");
        refreshReadout();
    }

    private void buildUi() {
        float d = getResources().getDisplayMetrics().density;
        int pad = (int) (12 * d);
        LinearLayout col = new LinearLayout(this); col.setOrientation(LinearLayout.VERTICAL); col.setPadding(pad, pad, pad, pad);

        TextView title = text("Android test platform", 19, true);
        TextView lede = text("Switch the variables, take a screenshot, read what the phone did. The refusal is the phone's own, asked for by this app; the pages are the proof site's own pages, loaded here unchanged.", 13, false);

        secureSwitch = new Switch(this); secureSwitch.setText("Capture refusal (secure window flag)"); secureSwitch.setChecked(true);
        secureSwitch.setOnCheckedChangeListener((b, on) -> setSecure(on));

        keyField = new EditText(this); keyField.setHint("Link key"); keyField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD); keyField.setSingleLine(true);
        pinField = new EditText(this); pinField.setHint("PIN"); pinField.setInputType(InputType.TYPE_CLASS_NUMBER); pinField.setSingleLine(true);

        LinearLayout row1 = row(); LinearLayout row2 = row();
        row1.addView(button("Native photo", v -> showNative()));
        row1.addView(button("trace/", v -> loadPage("trace/")));
        row1.addView(button("decoy/", v -> loadPage("web/research/decoy/")));
        row2.addView(button("above white", v -> loadPage("web/research/hdr/")));
        row2.addView(button("bench", v -> loadPage("web/research/bench/")));
        row2.addView(button("door", v -> loadPage("")));
        urlField = new EditText(this); urlField.setHint("Any address (loads inside this app)"); urlField.setInputType(InputType.TYPE_TEXT_VARIATION_URI); urlField.setSingleLine(true);
        LinearLayout row3 = row(); row3.addView(button("Load address", v -> loadUrl(urlField.getText().toString().trim())));

        status = text("Pick a content source.", 13, false);

        FrameLayout stageWrap = new FrameLayout(this); stageWrap.setBackgroundColor(Color.BLACK);
        photoView = new ImageView(this); photoView.setAdjustViewBounds(true); photoView.setScaleType(ImageView.ScaleType.FIT_CENTER); photoView.setLongClickable(false); photoView.setVisibility(View.GONE);
        web = new WebView(this);
        WebSettings ws = web.getSettings(); ws.setJavaScriptEnabled(true); ws.setDomStorageEnabled(true); ws.setMediaPlaybackRequiresUserGesture(false); ws.setLoadWithOverviewMode(true); ws.setUseWideViewPort(true);
        web.setWebViewClient(new WebViewClient() { @Override public void onPageFinished(WebView v, String url) { content = "web: " + url.replace(SITE, "site/").replaceAll("#.*$", "#k=…"); refreshReadout(); } });
        web.setWebChromeClient(new WebChromeClient());
        web.setVisibility(View.GONE);
        stageWrap.addView(photoView, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        stageWrap.addView(web, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (int) (900 * d)));

        TextView h2 = text("WHAT THIS PHONE IS DOING (measured on this phone)", 11, true);
        readout = text("", 12, false); readout.setTypeface(android.graphics.Typeface.MONOSPACE);

        for (View v : new View[] { title, lede, secureSwitch, keyField, pinField, row1, row2, urlField, row3, status, stageWrap, h2, readout }) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT); lp.bottomMargin = (int) (8 * d); col.addView(v, lp);
        }
        ScrollView scroll = new ScrollView(this); scroll.addView(col); setContentView(scroll);
    }
    private LinearLayout row() { LinearLayout r = new LinearLayout(this); r.setOrientation(LinearLayout.HORIZONTAL); return r; }
    private Button button(String label, View.OnClickListener l) { Button b = new Button(this); b.setText(label); b.setOnClickListener(l); b.setAllCaps(false); return b; }
    private TextView text(String s, int sp, boolean bold) { TextView t = new TextView(this); t.setText(s); t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp); if (bold) t.setTypeface(android.graphics.Typeface.DEFAULT_BOLD); return t; }

    private String key() { return keyField.getText().toString().trim(); }
    private void loadPage(String path) { loadUrl(SITE + path + (key().isEmpty() ? "" : "#k=" + key())); }
    private void loadUrl(String url) {
        if (url.isEmpty()) { status.setText("Type an address first."); return; }
        if (!url.startsWith("http://") && !url.startsWith("https://")) url = "https://" + url;
        photoView.setVisibility(View.GONE); web.setVisibility(View.VISIBLE);
        content = "loading " + url; status.setText("Loading inside this app, refusal " + (windowIsSecure() ? "ON" : "OFF") + ". Take a screenshot once the page shows the photo.");
        web.loadUrl(url); refreshReadout();
    }

    private void showNative() {
        final String secret = key(), pin = pinField.getText().toString().trim();
        if (secret.isEmpty() || !pin.matches("\\d{6}")) { status.setText("Enter the link key and the 6-digit PIN."); return; }
        web.setVisibility(View.GONE); photoView.setVisibility(View.VISIBLE); status.setText("Deriving the key and decrypting…");
        new Thread(() -> {
            byte[] plain = null; String error = null;
            try {
                byte[] file = readAsset("photo.enc"); ProofCrypto.Header h = ProofCrypto.parse(file);
                byte[] k = ProofCrypto.deriveKey(secret, pin, h); plain = ProofCrypto.decrypt(k, h); Arrays.fill(k, (byte) 0);
            } catch (javax.crypto.AEADBadTagException e) { error = "refused"; } catch (Exception e) { error = "error: " + e; }
            final byte[] plainF = plain; final String errorF = error;
            ui.post(() -> {
                if (plainF == null) { pinState = errorF; status.setText("refused".equals(errorF) ? "Wrong PIN or link key." : errorF); refreshReadout(); return; }
                try {
                    BitmapFactory.Options o = new BitmapFactory.Options(); o.inMutable = true; o.inPreferredConfig = Bitmap.Config.ARGB_8888;
                    Bitmap bmp = BitmapFactory.decodeByteArray(plainF, 0, plainF.length, o); Arrays.fill(plainF, (byte) 0);
                    String bucket = ProofMark.hourBucket(System.currentTimeMillis()); byte[] seed = ProofMark.seed(secret, pin, bucket); byte[] pattern = ProofMark.tilePattern(seed); markIdText = ProofMark.markId(seed);
                    int w = bmp.getWidth(), hh = bmp.getHeight(); int[] px = new int[w * hh]; bmp.getPixels(px, 0, w, 0, 0, w, hh); ProofMark.applyToPixels(px, w, hh, pattern); bmp.setPixels(px, 0, w, 0, 0, w, hh);
                    photoView.setImageBitmap(bmp); pinState = "accepted"; content = "native photo " + w + "x" + hh + ", marked";
                    status.setText("Native photo shown, refusal " + (windowIsSecure() ? "ON" : "OFF") + ". Take a screenshot now.");
                } catch (Exception e) { status.setText("error: " + e); }
                refreshReadout();
            });
        }, "ccs-lab-decrypt").start();
    }
    private byte[] readAsset(String name) throws java.io.IOException {
        try (InputStream in = getAssets().open(name); ByteArrayOutputStream out = new ByteArrayOutputStream()) { byte[] buf = new byte[16384]; int n; while ((n = in.read(buf)) > 0) out.write(buf, 0, n); return out.toByteArray(); }
    }

    private String displayFacts() {
        try {
            Display disp = Build.VERSION.SDK_INT >= 30 ? getDisplay() : getWindowManager().getDefaultDisplay();
            StringBuilder sb = new StringBuilder();
            sb.append(String.format(Locale.US, "%.0f Hz", disp.getRefreshRate()));
            if (Build.VERSION.SDK_INT >= 26) sb.append(disp.isHdr() ? ", HDR capable" : ", no HDR");
            if (Build.VERSION.SDK_INT >= 24) { int[] types = disp.getHdrCapabilities().getSupportedHdrTypes(); if (types.length > 0) sb.append(" (types ").append(Arrays.toString(types)).append(", max ").append(String.format(Locale.US, "%.0f", disp.getHdrCapabilities().getDesiredMaxLuminance())).append(" nits)"); }
            return sb.toString();
        } catch (Exception e) { return "unreadable: " + e; }
    }
    private String webViewVersion() {
        try { if (Build.VERSION.SDK_INT >= 26) { PackageInfo p = WebView.getCurrentWebViewPackage(); if (p != null) return p.packageName + " " + p.versionName; } } catch (Exception ignored) { }
        return "unknown";
    }
    private void refreshReadout() {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US); f.setTimeZone(TimeZone.getTimeZone("UTC"));
        readout.setText("Capture refusal: " + (windowIsSecure() ? "ON (secure flag read back from this window)" : "OFF (flag cleared)") + "\n"
                + "Content: " + content + "\n"
                + "PIN: " + pinState + "   mark: " + markIdText + "\n"
                + "Android: " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")   device: " + Build.MANUFACTURER + " " + Build.MODEL + "\n"
                + "Display: " + displayFacts() + "\n"
                + "Web view: " + webViewVersion() + "\n"
                + "Screenshot attempts: " + (Build.VERSION.SDK_INT >= 34 ? captureAttempts + " reported by Android" : "not reported before Android 14") + "\n"
                + "Device time: " + f.format(new Date()));
    }
}
