package com.candidcolor.proofviewer;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The CCSP1 file and its key. Pure Java with no Android class in it, so the same code runs under a
 * plain JDK for the cross-check against viewer.js (tools/CrossCheck.java) and inside the app.
 *
 * File layout (big-endian), written by tools/build-photo.mjs:
 *   bytes 0-4  "CCSP1"   bytes 5 version 1   bytes 6-9 PBKDF2 iterations
 *   bytes 10-25 salt (16)   bytes 26-37 AES-GCM IV (12)   bytes 38- ciphertext with the GCM tag appended
 * Key = PBKDF2-HMAC-SHA256(secret + ":" + pin, salt, iterations), 32 bytes, AES-256-GCM.
 */
public final class ProofCrypto {
    private ProofCrypto() {}

    public static final class Header {
        public final int iterations;
        public final byte[] salt;
        public final byte[] iv;
        public final byte[] ciphertext;
        Header(int iterations, byte[] salt, byte[] iv, byte[] ciphertext) {
            this.iterations = iterations; this.salt = salt; this.iv = iv; this.ciphertext = ciphertext;
        }
    }

    public static Header parse(byte[] file) {
        if (file.length < 38 + 16) throw new IllegalArgumentException("file too short for a CCSP1 header");
        String magic = new String(file, 0, 5, StandardCharsets.US_ASCII);
        if (!"CCSP1".equals(magic) || file[5] != 1) throw new IllegalArgumentException("not a CCSP1 version 1 file");
        int iterations = ((file[6] & 0xff) << 24) | ((file[7] & 0xff) << 16) | ((file[8] & 0xff) << 8) | (file[9] & 0xff);
        if (iterations <= 0) throw new IllegalArgumentException("bad iteration count");
        return new Header(iterations,
                Arrays.copyOfRange(file, 10, 26),
                Arrays.copyOfRange(file, 26, 38),
                Arrays.copyOfRange(file, 38, file.length));
    }

    /** PBKDF2 with HMAC-SHA256 (RFC 8018 section 5.2), written out so the derivation is ours and bit-identical to WebCrypto's. */
    public static byte[] pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int dkLen) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(password, "HmacSHA256"));
        int hLen = mac.getMacLength();
        int blocks = (dkLen + hLen - 1) / hLen;
        byte[] out = new byte[blocks * hLen];
        for (int i = 1; i <= blocks; i++) {
            mac.update(salt);
            mac.update(new byte[] { (byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i });
            byte[] u = mac.doFinal();
            byte[] t = u.clone();
            for (int j = 1; j < iterations; j++) {
                u = mac.doFinal(u);
                for (int k = 0; k < t.length; k++) t[k] ^= u[k];
            }
            System.arraycopy(t, 0, out, (i - 1) * hLen, hLen);
        }
        return Arrays.copyOf(out, dkLen);
    }

    public static byte[] deriveKey(String secret, String pin, Header h) throws GeneralSecurityException {
        byte[] password = (secret + ":" + pin).getBytes(StandardCharsets.UTF_8);
        return pbkdf2Sha256(password, h.salt, h.iterations, 32);
    }

    /** Throws javax.crypto.AEADBadTagException for a wrong key: the GCM tag does not verify, nothing is returned. */
    public static byte[] decrypt(byte[] key, Header h) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, h.iv));
        return c.doFinal(h.ciphertext);
    }
}
