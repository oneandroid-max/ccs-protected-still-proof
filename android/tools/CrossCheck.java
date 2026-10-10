// android/tools/CrossCheck.java — prove the Java port equals the JavaScript original before anything is installed.
//
//   javac -d out ../app/src/main/java/com/candidcolor/proofviewer/ProofCrypto.java \
//         ../app/src/main/java/com/candidcolor/proofviewer/ProofMark.java CrossCheck.java
//   java -cp out CrossCheck <file.enc> <secret> <pin> <YYYY-MM-DDTHH> [--canonical]
//
// Without --canonical: two JSON lines (the facts, then the wrong-PIN result). With --canonical: the one
// line every port must print identically (see tools/cross-check.mjs), which CI diffs against
// tests/vectors/expected.txt. markedRampSha256 applies the mark to a synthetic 300×200 RGB ramp through
// ProofMark.applyToPixels, the exact code the viewer uses, and hashes the RGB bytes in row order.
import com.candidcolor.proofviewer.ProofCrypto;
import com.candidcolor.proofviewer.ProofMark;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

public class CrossCheck {
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x & 0xff)); return s.toString(); }
    static byte[] sha(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }

    static String markedRampSha256(byte[] pattern) throws Exception {
        final int W = 300, H = 200;
        int[] px = new int[W * H];
        for (int y = 0; y < H; y++) for (int x = 0; x < W; x++) px[y * W + x] = 0xff000000 | ((x & 255) << 16) | ((y & 255) << 8) | ((x + y) & 255);
        ProofMark.applyToPixels(px, W, H, pattern);
        byte[] rgb = new byte[W * H * 3];
        for (int p = 0; p < W * H; p++) { rgb[p * 3] = (byte) (px[p] >> 16); rgb[p * 3 + 1] = (byte) (px[p] >> 8); rgb[p * 3 + 2] = (byte) px[p]; }
        return hex(sha(rgb));
    }

    public static void main(String[] a) throws Exception {
        if (a.length < 4) { System.err.println("usage: <file.enc> <secret> <pin> <YYYY-MM-DDTHH> [--canonical]"); System.exit(2); }
        boolean canonical = a.length > 4 && "--canonical".equals(a[4]);
        byte[] file = Files.readAllBytes(Paths.get(a[0]));
        String secret = a[1], pin = a[2], bucket = a[3];
        ProofCrypto.Header h = ProofCrypto.parse(file);
        long t0 = System.nanoTime();
        byte[] key = ProofCrypto.deriveKey(secret, pin, h);
        long t1 = System.nanoTime();
        byte[] plain = ProofCrypto.decrypt(key, h);
        long t2 = System.nanoTime();
        byte[] seed = ProofMark.seed(secret, pin, bucket);
        byte[] pattern = ProofMark.tilePattern(seed);
        int plus = 0; for (byte p : pattern) if (p == 1) plus++;
        String plainSha = hex(sha(plain)), magic = hex(Arrays.copyOf(plain, 3)), id = ProofMark.markId(seed), patSha = hex(sha(pattern)), ramp = markedRampSha256(pattern);

        String wrong = pin.equals("000000") ? "111111" : "000000";
        String wrongResult;
        try { ProofCrypto.decrypt(ProofCrypto.deriveKey(secret, wrong, h), h); wrongResult = "DECRYPTED"; }
        catch (javax.crypto.AEADBadTagException e) { wrongResult = "refused"; }

        if (canonical) {
            System.out.println("ccs-vector-v1 plainBytes=" + plain.length + " plainSha256=" + plainSha + " jpegMagic=" + magic
                    + " markId=" + id + " patternSha256=" + patSha + " patternPlusOnes=" + plus + " markedRampSha256=" + ramp + " wrongPin=" + wrongResult);
        } else {
            System.out.println("{\"iterations\":" + h.iterations + ",\"plainBytes\":" + plain.length + ",\"plainSha256\":\"" + plainSha + "\""
                    + ",\"jpegMagic\":\"" + magic + "\",\"pbkdf2Ms\":" + Math.round((t1 - t0) / 1e4) / 100.0 + ",\"decryptMs\":" + Math.round((t2 - t1) / 1e4) / 100.0
                    + ",\"bucket\":\"" + bucket + "\",\"markId\":\"" + id + "\",\"patternSha256\":\"" + patSha + "\",\"patternPlusOnes\":" + plus
                    + ",\"markedRampSha256\":\"" + ramp + "\"}");
            System.out.println("{\"wrongPin\":\"" + wrong + "\",\"result\":\"" + wrongResult + "\"}");
        }
        if (!"refused".equals(wrongResult)) System.exit(1);
    }
}
