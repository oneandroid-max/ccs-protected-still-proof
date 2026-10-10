// android/tools/CrossCheck.java — prove the Java port equals the JavaScript original before anything is installed.
//
//   javac -d out ../app/src/main/java/com/candidcolor/proofviewer/ProofCrypto.java \
//         ../app/src/main/java/com/candidcolor/proofviewer/ProofMark.java CrossCheck.java
//   java -cp out CrossCheck ../../photo.enc <secret> <pin> <YYYY-MM-DDTHH>
//
// Prints the decrypted byte count, its SHA-256, the JPEG magic, the PBKDF2 and decrypt times, the mark id
// and the SHA-256 of the tile pattern. tools/cross-check.mjs prints the same from mark.js and WebCrypto;
// the two outputs must agree byte for byte, and a wrong PIN must be refused here.
import com.candidcolor.proofviewer.ProofCrypto;
import com.candidcolor.proofviewer.ProofMark;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

public class CrossCheck {
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x & 0xff)); return s.toString(); }
    static byte[] sha(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }

    public static void main(String[] a) throws Exception {
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
        System.out.println("{\"iterations\":" + h.iterations
                + ",\"plainBytes\":" + plain.length
                + ",\"plainSha256\":\"" + hex(sha(plain)) + "\""
                + ",\"jpegMagic\":\"" + hex(Arrays.copyOf(plain, 3)) + "\""
                + ",\"pbkdf2Ms\":" + Math.round((t1 - t0) / 1e4) / 100.0
                + ",\"decryptMs\":" + Math.round((t2 - t1) / 1e4) / 100.0
                + ",\"bucket\":\"" + bucket + "\""
                + ",\"markId\":\"" + ProofMark.markId(seed) + "\""
                + ",\"patternSha256\":\"" + hex(sha(pattern)) + "\""
                + ",\"patternPlusOnes\":" + plus + "}");
        String wrong = pin.equals("000000") ? "111111" : "000000";
        try {
            ProofCrypto.decrypt(ProofCrypto.deriveKey(secret, wrong, h), h);
            System.out.println("{\"wrongPin\":\"" + wrong + "\",\"result\":\"DECRYPTED — FAIL\"}");
            System.exit(1);
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("{\"wrongPin\":\"" + wrong + "\",\"result\":\"refused (AEADBadTagException)\"}");
        }
    }
}
