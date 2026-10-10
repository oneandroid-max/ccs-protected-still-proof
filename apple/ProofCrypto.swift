// apple/ProofCrypto.swift — the CCSP1 file and its key on Apple platforms. Shared by the iPhone and
// Mac viewers and by the command-line cross-check. PBKDF2 comes from CommonCrypto and AES-GCM from
// CryptoKit, both parts of the operating system; the file format and the derivation rule are ours and
// identical to viewer.js, ProofCrypto.java and proofcore.c.
import Foundation
import CryptoKit
import CommonCrypto

struct CCSP1Header {
    let iterations: UInt32
    let salt: Data
    let iv: Data
    let ciphertext: Data   // with the 16-byte GCM tag appended

    /// "CCSP1", version 1, iterations (uint32 big-endian), salt[16], iv[12], ciphertext+tag.
    static func parse(_ file: Data) -> CCSP1Header? {
        let b = [UInt8](file)
        guard b.count >= 38 + 16, b[0] == 0x43, b[1] == 0x43, b[2] == 0x53, b[3] == 0x50, b[4] == 0x31, b[5] == 1 else { return nil }
        let it = (UInt32(b[6]) << 24) | (UInt32(b[7]) << 16) | (UInt32(b[8]) << 8) | UInt32(b[9])
        guard it > 0 else { return nil }
        return CCSP1Header(iterations: it, salt: Data(b[10..<26]), iv: Data(b[26..<38]), ciphertext: Data(b[38...]))
    }
}

enum ProofCryptoError: Error { case wrongKey, malformed, derivationFailed }

enum ProofCrypto {
    /// PBKDF2-HMAC-SHA256(secret + ":" + pin, salt, iterations) → 32 bytes.
    static func deriveKey(secret: String, pin: String, header: CCSP1Header) throws -> Data {
        let password = "\(secret):\(pin)"
        let salt = [UInt8](header.salt)
        var out = [UInt8](repeating: 0, count: 32)
        let rc: Int32 = password.withCString { cstr in
            salt.withUnsafeBufferPointer { sp in
                out.withUnsafeMutableBufferPointer { op in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), cstr, strlen(cstr), sp.baseAddress, sp.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), header.iterations, op.baseAddress, 32)
                }
            }
        }
        guard rc == kCCSuccess else { throw ProofCryptoError.derivationFailed }
        return Data(out)
    }

    /// AES-256-GCM. A wrong key fails the tag check and returns nothing (wrongKey).
    static func decrypt(key: Data, header: CCSP1Header) throws -> Data {
        guard header.ciphertext.count >= 16 else { throw ProofCryptoError.malformed }
        let nonce = try AES.GCM.Nonce(data: header.iv)
        let body = header.ciphertext.prefix(header.ciphertext.count - 16)
        let tag = header.ciphertext.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: body, tag: tag)
        do { return try AES.GCM.open(box, using: SymmetricKey(data: key)) }
        catch CryptoKitError.authenticationFailure { throw ProofCryptoError.wrongKey }
    }

    static func sha256Hex(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}
