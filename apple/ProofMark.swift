// apple/ProofMark.swift — the viewer mark, identical to mark.js, ProofMark.java and proofcore.c:
// SHA-256("ccs-mark-v1:secret:pin:hour") → xorshift128 → 128×128 tile of ±1, added at ±3/255 to R, G, B.
import Foundation
import CryptoKit

enum ProofMark {
    static let tile = 128
    static let amplitude = 3

    /// "YYYY-MM-DDTHH" in UTC.
    static func hourBucket(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH"
        return f.string(from: date)
    }

    static func seed(secret: String, pin: String, hour: String) -> [UInt8] {
        Array(SHA256.hash(data: Data("ccs-mark-v1:\(secret):\(pin):\(hour)".utf8)))
    }

    private static func u32(_ b: [UInt8], _ i: Int) -> UInt32 {
        (UInt32(b[i]) << 24) | (UInt32(b[i + 1]) << 16) | (UInt32(b[i + 2]) << 8) | UInt32(b[i + 3])
    }

    /// Index = (y % tile) * tile + (x % tile). Values are +1 or −1.
    static func tilePattern(_ seed: [UInt8]) -> [Int8] {
        var x = u32(seed, 0), y = u32(seed, 4), z = u32(seed, 8), w = u32(seed, 12)
        if x == 0 { x = 0x9e3779b9 }
        if y == 0 { y = 0x243f6a88 }
        if z == 0 { z = 0xb7e15162 }
        if w == 0 { w = 0x6a09e667 }
        var p = [Int8](repeating: 0, count: tile * tile)
        for i in 0..<p.count {
            let t = x ^ (x << 11)
            x = y; y = z; z = w
            w = (w ^ (w >> 19)) ^ (t ^ (t >> 8))
            p[i] = ((w >> 16) & 1) != 0 ? 1 : -1
        }
        return p
    }

    static func markId(_ seed: [UInt8]) -> String { seed[0..<4].map { String(format: "%02x", $0) }.joined() }

    /// Adds the mark in place to 4-byte pixels; offR/offG/offB name the channel bytes within a pixel.
    static func apply(_ px: inout [UInt8], width: Int, height: Int, stride: Int, offR: Int, offG: Int, offB: Int, pattern: [Int8]) {
        func clamp(_ v: Int) -> UInt8 { UInt8(max(0, min(255, v))) }
        for y in 0..<height {
            let row = (y % tile) * tile
            var i = y * stride
            for x in 0..<width {
                let m = amplitude * Int(pattern[row + (x % tile)])
                px[i + offR] = clamp(Int(px[i + offR]) + m)
                px[i + offG] = clamp(Int(px[i + offG]) + m)
                px[i + offB] = clamp(Int(px[i + offB]) + m)
                i += 4
            }
        }
    }
}
