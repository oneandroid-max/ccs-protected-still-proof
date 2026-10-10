package com.candidcolor.proofviewer;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

/**
 * The viewer mark: a seeded ±1 tile pattern, identical to mark.js so the page, the detector and this
 * app all agree. Seed = SHA-256("ccs-mark-v1:" + secret + ":" + pin + ":" + hour), generator =
 * Marsaglia xorshift128 over the first 16 seed bytes, pattern = TILE×TILE of +1/−1, applied at ±3 of 255
 * on every channel. Pure Java: no Android class.
 */
public final class ProofMark {
    private ProofMark() {}

    public static final int TILE = 128;
    public static final int AMPLITUDE = 3;

    /** "YYYY-MM-DDTHH" in UTC, the same bucket mark.js derives from Date.toISOString(). */
    public static String hourBucket(long epochMillis) {
        SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH", Locale.US);
        f.setTimeZone(TimeZone.getTimeZone("UTC"));
        return f.format(new Date(epochMillis));
    }

    public static byte[] seed(String secret, String pin, String bucket) throws GeneralSecurityException {
        String s = "ccs-mark-v1:" + secret + ":" + pin + ":" + bucket;
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    }

    private static int u32(byte[] b, int i) {
        return ((b[i] & 0xff) << 24) | ((b[i + 1] & 0xff) << 16) | ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff);
    }

    /** The TILE×TILE pattern for a seed. Index = (y % TILE) * TILE + (x % TILE). Values are +1 or −1. */
    public static byte[] tilePattern(byte[] seed) {
        int x = u32(seed, 0); if (x == 0) x = 0x9e3779b9;
        int y = u32(seed, 4); if (y == 0) y = 0x243f6a88;
        int z = u32(seed, 8); if (z == 0) z = 0xb7e15162;
        int w = u32(seed, 12); if (w == 0) w = 0x6a09e667;
        byte[] p = new byte[TILE * TILE];
        for (int i = 0; i < p.length; i++) {
            int t = x ^ (x << 11);
            x = y; y = z; z = w;
            w = (w ^ (w >>> 19)) ^ (t ^ (t >>> 8));
            p[i] = (byte) ((((w >>> 16) & 1) != 0) ? 1 : -1);
        }
        return p;
    }

    /** Eight hex characters naming a seed on the readout without revealing it. */
    public static String markId(byte[] seed) {
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < 4; i++) sb.append(String.format(Locale.US, "%02x", seed[i] & 0xff));
        return sb.toString();
    }

    private static int clamp(int v) { return v < 0 ? 0 : (v > 255 ? 255 : v); }

    /** Adds the mark to ARGB pixels in place, the same arithmetic as applyMark() in viewer.js. */
    public static void applyToPixels(int[] px, int w, int h, byte[] pattern) {
        for (int y = 0; y < h; y++) {
            int row = (y % TILE) * TILE;
            int base = y * w;
            for (int x = 0; x < w; x++) {
                int m = AMPLITUDE * pattern[row + (x % TILE)];
                int p = px[base + x];
                int r = clamp(((p >> 16) & 0xff) + m);
                int g = clamp(((p >> 8) & 0xff) + m);
                int b = clamp((p & 0xff) + m);
                px[base + x] = (p & 0xff000000) | (r << 16) | (g << 8) | b;
            }
        }
    }
}
