// apple/crosscheck/main.swift — the Apple command-line cross-check: prints the canonical line CI diffs against
// tests/vectors/expected.txt.  swiftc apple/ProofCrypto.swift apple/ProofMark.swift apple/crosscheck/main.swift -o crosscheck
//   crosscheck <file.enc> <secret> <pin> <YYYY-MM-DDTHH> --canonical
import Foundation
import CryptoKit

let args = CommandLine.arguments
guard args.count >= 5 else { FileHandle.standardError.write(Data("usage: <file.enc> <secret> <pin> <YYYY-MM-DDTHH> [--canonical]\n".utf8)); exit(2) }
let canonical = args.count > 5 && args[5] == "--canonical"
guard let file = FileManager.default.contents(atPath: args[1]), let header = CCSP1Header.parse(file) else { FileHandle.standardError.write(Data("not a CCSP1 file\n".utf8)); exit(1) }
let secret = args[2], pin = args[3], hour = args[4]
let t0 = Date()
let key = try ProofCrypto.deriveKey(secret: secret, pin: pin, header: header)
let t1 = Date()
let plain = try ProofCrypto.decrypt(key: key, header: header)
let t2 = Date()
let seed = ProofMark.seed(secret: secret, pin: pin, hour: hour)
let pattern = ProofMark.tilePattern(seed)
let plus = pattern.filter { $0 == 1 }.count
let patternSha = ProofCrypto.sha256Hex(Data(pattern.map { UInt8(bitPattern: $0) }))
let magic = plain.prefix(3).map { String(format: "%02x", $0) }.joined()
// the synthetic 300×200 ramp (R=x, G=y, B=x+y), marked with the same apply() the viewers use, hashed in RGB row order
let W = 300, H = 200
var ramp = [UInt8](repeating: 0, count: W * H * 4)
for y in 0..<H { for x in 0..<W { let i = (y * W + x) * 4; ramp[i] = UInt8(x & 255); ramp[i + 1] = UInt8(y & 255); ramp[i + 2] = UInt8((x + y) & 255); ramp[i + 3] = 255 } }
ProofMark.apply(&ramp, width: W, height: H, stride: W * 4, offR: 0, offG: 1, offB: 2, pattern: pattern)
var rgb = [UInt8](repeating: 0, count: W * H * 3)
for p in 0..<(W * H) { rgb[p * 3] = ramp[p * 4]; rgb[p * 3 + 1] = ramp[p * 4 + 1]; rgb[p * 3 + 2] = ramp[p * 4 + 2] }
let rampSha = ProofCrypto.sha256Hex(Data(rgb))
let wrong = pin == "000000" ? "111111" : "000000"
var wrongResult = "DECRYPTED"
do { _ = try ProofCrypto.decrypt(key: try ProofCrypto.deriveKey(secret: secret, pin: wrong, header: header), header: header) } catch ProofCryptoError.wrongKey { wrongResult = "refused" } catch { wrongResult = "error" }
if canonical {
    print("ccs-vector-v1 plainBytes=\(plain.count) plainSha256=\(ProofCrypto.sha256Hex(plain)) jpegMagic=\(magic) markId=\(ProofMark.markId(seed)) patternSha256=\(patternSha) patternPlusOnes=\(plus) markedRampSha256=\(rampSha) wrongPin=\(wrongResult)")
} else {
    print("{\"iterations\":\(header.iterations),\"plainBytes\":\(plain.count),\"plainSha256\":\"\(ProofCrypto.sha256Hex(plain))\",\"jpegMagic\":\"\(magic)\",\"pbkdf2Ms\":\(Int(t1.timeIntervalSince(t0) * 1000)),\"decryptMs\":\(Int(t2.timeIntervalSince(t1) * 1000)),\"bucket\":\"\(hour)\",\"markId\":\"\(ProofMark.markId(seed))\",\"patternSha256\":\"\(patternSha)\",\"patternPlusOnes\":\(plus),\"markedRampSha256\":\"\(rampSha)\"}")
    print("{\"wrongPin\":\"\(wrong)\",\"result\":\"\(wrongResult)\"}")
}
exit(wrongResult == "refused" ? 0 : 1)
