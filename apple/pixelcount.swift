// apple/pixelcount.swift — counts magenta pixels in a PNG (the probe rectangle), for the simulator
// screenshot in CI.   swift apple/pixelcount.swift <image.png>  → one JSON line
import Foundation
import CoreGraphics
import ImageIO

let path = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil), let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { print("{\"error\":\"cannot read \(path)\"}"); exit(1) }
let w = img.width, h = img.height
var px = [UInt8](repeating: 0, count: w * h * 4)
guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { print("{\"error\":\"no context\"}"); exit(1) }
ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
var magenta = 0, black = 0
for p in 0..<(w * h) { let r = px[p * 4], g = px[p * 4 + 1], b = px[p * 4 + 2]; if r > 200 && g < 60 && b > 200 { magenta += 1 }; if r < 12 && g < 12 && b < 12 { black += 1 } }
print("{\"image\":\"\(path)\",\"size\":\"\(w)x\(h)\",\"magentaPixels\":\(magenta),\"magentaFraction\":\(String(format: "%.4f", Double(magenta) / Double(w * h))),\"blackFraction\":\(String(format: "%.4f", Double(black) / Double(w * h)))}")
