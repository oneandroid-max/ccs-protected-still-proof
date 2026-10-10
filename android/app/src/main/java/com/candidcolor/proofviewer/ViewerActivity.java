package com.candidcolor.proofviewer;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.MediaStore;
import android.text.InputType;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * The Android viewer of the self-defending proof. Our own code on top of the Android framework and
 * nothing else: no library, no vendor service, no network call.
 *
 * The block: the window is flagged secure before anything is drawn, so Android itself refuses to put
 * it in a screenshot, a screen recording, a cast or the recent-apps thumbnail. The photo is drawn
 * clean; nothing is distorted for the viewer. Fail closed: the photo is decrypted only after the flag
 * is measured on the window. Everything on the readout is measured on this phone.
 */
public final class ViewerActivity extends Activity {
    private EditText keyField, pinField;
    private Button showButton, cardButton;
    private ImageView photoView;
    private TextView status, readout;

    private Bitmap shown;                 // the marked photo on screen
    private byte[] pattern;               // this viewer's tile
    private String pinState = "waiting";
    private String markIdText = "—", bucket = "—", timing = "—";
    private int captureAttempts = 0;
    private Object captureCallback;       // Activity.ScreenCaptureCallback on Android 14+; kept as Object so older systems never load the class
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        // The refusal, asked for before the first frame exists.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        buildUi();
        String key = keyFromIntent(getIntent());
        if (key != null) keyField.setText(key);
        refreshReadout();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        String key = keyFromIntent(intent);
        if (key != null) keyField.setText(key);
    }

    @Override
    protected void onStart() {
        super.onStart();
        if (Build.VERSION.SDK_INT >= 34) registerCaptureCallback();
    }

    @Override
    protected void onStop() {
        if (Build.VERSION.SDK_INT >= 34) unregisterCaptureCallback();
        super.onStop();
    }

    private void registerCaptureCallback() {
        Activity.ScreenCaptureCallback cb = () -> { captureAttempts++; refreshReadout(); };
        captureCallback = cb;
        registerScreenCaptureCallback(getMainExecutor(), cb);
    }

    private void unregisterCaptureCallback() {
        if (captureCallback != null) {
            unregisterScreenCaptureCallback((Activity.ScreenCaptureCallback) captureCallback);
            captureCallback = null;
        }
    }

    // ---- the page ----------------------------------------------------------------------------

    private void buildUi() {
        float d = getResources().getDisplayMetrics().density;
        int pad = (int) (16 * d);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(pad, pad, pad, pad);

        TextView title = text("The self-defending proof, Android viewer", 20, true);
        TextView lede = text("The photo is stored only encrypted inside this app. The key comes from the link and the PIN. "
                + "This window is flagged secure, so Android refuses to put it in a screenshot, a screen recording, a cast "
                + "or the recent-apps thumbnail. The photo is drawn clean. Every view carries an invisible mark naming the "
                + "viewer and the hour. No vendor service is involved.", 14, false);

        keyField = new EditText(this);
        keyField.setHint("Link key (the part after #k= in the link)");
        keyField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        keyField.setSingleLine(true);

        pinField = new EditText(this);
        pinField.setHint("PIN (6 digits)");
        pinField.setInputType(InputType.TYPE_CLASS_NUMBER);
        pinField.setSingleLine(true);

        showButton = new Button(this);
        showButton.setText("Show the photo");
        showButton.setOnClickListener(v -> show());

        photoView = new ImageView(this);
        photoView.setAdjustViewBounds(true);
        photoView.setScaleType(ImageView.ScaleType.FIT_CENTER);
        photoView.setBackgroundColor(Color.BLACK);
        photoView.setMinimumHeight((int) (160 * d));
        photoView.setLongClickable(false);     // a long press offers nothing: there is no save, no share, no copy
        photoView.setContentDescription("The protected photo");

        status = text("Type the PIN to open the photo.", 14, false);
        TextView credit = text("© Candid Color Systems · this view is marked to its viewer", 12, false);

        cardButton = new Button(this);
        cardButton.setText("Save the share card");
        cardButton.setEnabled(false);
        cardButton.setOnClickListener(v -> saveShareCard());

        TextView h2 = text("WHAT THIS PHONE IS DOING (measured on this phone)", 12, true);
        readout = text("", 13, false);
        readout.setTypeface(Typeface.MONOSPACE);

        TextView tryIt = text("Try it\n"
                + "1. Type the PIN and tap Show the photo. The photo appears clean, with no shimmer.\n"
                + "2. Take a screenshot with the phone's buttons. Android either refuses, or the saved image has a black box where the photo is.\n"
                + "3. Start a screen recording, stop it, and play it back. The photo area is black.\n"
                + "4. Cast or mirror the screen to a TV. The photo area is black there.\n"
                + "5. Open the recent-apps view. This app's thumbnail is blank.\n"
                + "6. Long-press the photo. Nothing is offered.\n"
                + "7. Save the share card: the honest copy a family is given, credited and marked.", 14, false);
        TextView limits = text("What this cannot do\n"
                + "A camera pointed at the screen still photographs it, and that photo carries the viewer's mark. "
                + "The refusal is Android's own, asked for by this app; the key, the file, the mark and the viewer are ours.", 14, false);

        for (View v : new View[] { title, lede, keyField, pinField, showButton, photoView, status, credit, cardButton, h2, readout, tryIt, limits }) {
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.bottomMargin = (int) (10 * d);
            col.addView(v, lp);
        }
        ScrollView scroll = new ScrollView(this);
        scroll.addView(col);
        setContentView(scroll);
    }

    private TextView text(String s, int sp, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    /** The link key from https://…/ccs-protected-still-proof/#k=… or ccsproof://open?k=…; null when the app was opened from its icon. */
    private static String keyFromIntent(Intent intent) {
        if (intent == null || intent.getData() == null) return null;
        Uri u = intent.getData();
        try {
            String f = u.getFragment();
            if (f != null) for (String part : f.split("&")) if (part.startsWith("k=")) return part.substring(2);
            String q = u.getQueryParameter("k");
            if (q != null && !q.isEmpty()) return q;
        } catch (UnsupportedOperationException ignored) { /* an opaque URI has no query */ }
        return null;
    }

    private boolean windowIsSecure() {
        return (getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0;
    }

    // ---- opening the photo --------------------------------------------------------------------

    private void show() {
        final String secret = keyField.getText().toString().trim();
        final String pin = pinField.getText().toString().trim();
        if (secret.isEmpty() || !pin.matches("\\d{6}")) {
            status.setText("Enter the link key and the 6-digit PIN.");
            return;
        }
        // Fail closed: no decryption unless the refusal is measured on this window right now.
        if (!windowIsSecure()) {
            pinState = "not tried: window not secure";
            status.setText("This window is not flagged secure, so the photo stays hidden.");
            refreshReadout();
            return;
        }
        showButton.setEnabled(false);
        status.setText("Deriving the key and decrypting…");
        new Thread(() -> {
            byte[] plain = null;
            String error = null;
            long keyMs = 0, decMs = 0;
            try {
                byte[] file = readAsset("photo.enc");
                ProofCrypto.Header h = ProofCrypto.parse(file);
                long a = System.currentTimeMillis();
                byte[] key = ProofCrypto.deriveKey(secret, pin, h);
                long b = System.currentTimeMillis();
                keyMs = b - a;
                plain = ProofCrypto.decrypt(key, h);
                decMs = System.currentTimeMillis() - b;
                Arrays.fill(key, (byte) 0);
            } catch (javax.crypto.AEADBadTagException e) {
                error = "refused";
            } catch (Exception e) {
                error = "error: " + e;
            }
            final byte[] plainF = plain;
            final String errorF = error;
            final long keyMsF = keyMs, decMsF = decMs;
            ui.post(() -> onDecrypted(secret, pin, plainF, errorF, keyMsF, decMsF));
        }, "ccs-decrypt").start();
    }

    private void onDecrypted(String secret, String pin, byte[] plain, String error, long keyMs, long decMs) {
        showButton.setEnabled(true);
        if (plain == null) {
            pinState = "refused".equals(error) ? "refused" : error;
            status.setText("refused".equals(error) ? "Wrong PIN or link key: nothing to show." : error);
            refreshReadout();
            return;
        }
        try {
            BitmapFactory.Options o = new BitmapFactory.Options();
            o.inMutable = true;
            o.inPreferredConfig = Bitmap.Config.ARGB_8888;
            Bitmap bmp = BitmapFactory.decodeByteArray(plain, 0, plain.length, o);
            Arrays.fill(plain, (byte) 0);           // the clear bytes live only until the bitmap exists
            if (bmp == null) { status.setText("The photo could not be decoded."); return; }

            bucket = ProofMark.hourBucket(System.currentTimeMillis());
            byte[] seed = ProofMark.seed(secret, pin, bucket);
            pattern = ProofMark.tilePattern(seed);
            markIdText = ProofMark.markId(seed);
            int w = bmp.getWidth(), h = bmp.getHeight();
            int[] px = new int[w * h];
            bmp.getPixels(px, 0, w, 0, 0, w, h);
            ProofMark.applyToPixels(px, w, h, pattern);
            bmp.setPixels(px, 0, w, 0, 0, w, h);

            shown = bmp;
            photoView.setImageBitmap(bmp);
            pinState = "accepted";
            timing = "key " + keyMs + " ms, decrypt " + decMs + " ms";
            status.setText("Showing the photo. Take a screenshot now.");
            cardButton.setEnabled(true);
            refreshReadout();
        } catch (Exception e) {
            status.setText("error: " + e);
        }
    }

    private byte[] readAsset(String name) throws java.io.IOException {
        try (InputStream in = getAssets().open(name); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }

    // ---- the readout: only what this phone measured ------------------------------------------

    private void refreshReadout() {
        StringBuilder sb = new StringBuilder();
        sb.append("PIN: ").append(pinState).append('\n');
        sb.append("Capture refusal: ").append(windowIsSecure() ? "ON (secure flag read back from this window)" : "OFF").append('\n');
        sb.append("Android: ").append(Build.VERSION.RELEASE).append(" (API ").append(Build.VERSION.SDK_INT).append(")\n");
        sb.append("Device: ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append('\n');
        sb.append("Photo: ").append(shown == null ? "not shown" : shown.getWidth() + "×" + shown.getHeight() + " px, drawn clean").append('\n');
        sb.append("Viewer mark: ").append(markIdText).append(shown == null ? "" : " (hour " + bucket + ")").append('\n');
        sb.append("Timing: ").append(timing).append('\n');
        sb.append("Screenshot attempts: ").append(Build.VERSION.SDK_INT >= 34 ? captureAttempts + " reported by Android" : "not reported before Android 14").append('\n');
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        sb.append("Device time: ").append(f.format(new Date()));
        readout.setText(sb);
    }

    // ---- the share the family is given --------------------------------------------------------

    private void saveShareCard() {
        if (shown == null || pattern == null) return;
        if (Build.VERSION.SDK_INT < 29) {
            status.setText("Saving the share card needs Android 10 or newer on this proof.");
            return;
        }
        final int cw = 600, band = 64;
        final int ch = Math.round(cw * (float) shown.getHeight() / shown.getWidth());
        Bitmap card = Bitmap.createBitmap(cw, ch + band, Bitmap.Config.ARGB_8888);
        Canvas c = new Canvas(card);
        Bitmap scaled = Bitmap.createScaledBitmap(shown, cw, ch, true);
        c.drawBitmap(scaled, 0, 0, null);
        int[] px = new int[cw * ch];
        card.getPixels(px, 0, cw, 0, 0, cw, ch);
        ProofMark.applyToPixels(px, cw, ch, pattern);      // the card carries the viewer's mark at its own size
        card.setPixels(px, 0, cw, 0, 0, cw, ch);
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        p.setColor(0xFF011B51);
        c.drawRect(0, ch, cw, ch + band, p);
        p.setColor(Color.WHITE);
        p.setTypeface(Typeface.DEFAULT_BOLD);
        p.setTextSize(18);
        c.drawText("Candid Color Systems", 16, ch + 27, p);
        p.setTypeface(Typeface.DEFAULT);
        p.setTextSize(14);
        c.drawText("Shared with the family · gallery: (your gallery link here) · marked to its viewer", 16, ch + 50, p);
        try {
            ContentValues v = new ContentValues();
            v.put(MediaStore.Images.Media.DISPLAY_NAME, "ccs-share-card-" + markIdText + ".jpg");
            v.put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg");
            v.put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/CCS Proof");
            Uri uri = getContentResolver().insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, v);
            if (uri == null) throw new java.io.IOException("the gallery refused the file");
            try (OutputStream out = getContentResolver().openOutputStream(uri)) {
                if (out == null) throw new java.io.IOException("could not open the gallery file");
                card.compress(Bitmap.CompressFormat.JPEG, 90, out);
            }
            status.setText("Share card saved to Pictures/CCS Proof, marked " + markIdText + ".");
            Intent send = new Intent(Intent.ACTION_SEND);
            send.setType("image/jpeg");
            send.putExtra(Intent.EXTRA_STREAM, uri);
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(send, "Share the card"));
        } catch (Exception e) {
            status.setText("Could not save the share card: " + e);
        }
    }
}
