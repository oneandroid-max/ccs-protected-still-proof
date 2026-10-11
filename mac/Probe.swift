// mac/Probe.swift — does macOS still leave a window with sharingType .none out of a capture?
//   swiftc -O -framework AppKit -framework AVFoundation mac/Probe.swift -o probe
//   ./probe none|readOnly [--out=probe.json]
// Draws a flat magenta window with white stripes, waits a second, then measures two capture paths with
// the system's own tool: a screenshot (/usr/sbin/screencapture -x -R) and a two-second recording
// (/usr/sbin/screencapture -V 2 -R, which records through the system's screen-capture framework, the
// path QuickTime and screen sharing use). Each result is the fraction of magenta pixels in the capture
// and a verdict. The readOnly run is the gate: if even that capture shows no magenta, this machine or
// this session cannot measure, and the result says so. One JSON line, nothing else.
import AppKit
import AVFoundation

final class StripeView: NSView {
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        NSColor(red: 1, green: 0, blue: 1, alpha: 1).setFill(); bounds.fill()
        NSColor.white.setFill()
        var x = bounds.minX
        while x < bounds.maxX { NSRect(x: x, y: bounds.minY, width: 12, height: bounds.height).fill(); x += 48 }
    }
}

func magenta(in img: CGImage) -> (fraction: Double, pixels: Int, size: String) {
    let w = img.width, h = img.height
    var px = [UInt8](repeating: 0, count: w * h * 4)
    guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { return (-1, 0, "0x0") }
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
    var m = 0
    for p in 0..<(w * h) { let r = px[p * 4], g = px[p * 4 + 1], b = px[p * 4 + 2]; if r > 200 && g < 60 && b > 200 { m += 1 } }
    return (Double(m) / Double(w * h), m, "\(w)x\(h)")
}
func verdict(_ fraction: Double, _ pixels: Int) -> String {
    if fraction < 0 { return "unreadable" }
    if fraction > 0.5 || pixels > 20000 { return "NOT excluded (the window is in the capture)" }
    if pixels < 50 { return "excluded (the window is not in the capture)" }
    return "partial"
}
func run(_ args: [String]) -> Int32 {
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture"); p.arguments = args
    do { try p.run(); p.waitUntilExit(); return p.terminationStatus } catch { return -2 }
}

let args = CommandLine.arguments
var sharing = "none"; var out = "probe.json"
for a in args.dropFirst() { if a.hasPrefix("--out=") { out = String(a.dropFirst(6)) } else if a == "none" || a == "readOnly" { sharing = a } }

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let window = NSWindow(contentRect: NSRect(x: 200, y: 200, width: 420, height: 320), styleMask: [.titled], backing: .buffered, defer: false)
window.title = "CCS probe"
window.contentView = StripeView(frame: window.contentView!.bounds)
window.sharingType = sharing == "none" ? .none : .readOnly
let readBack: String = { switch window.sharingType { case .none: return "none"; case .readOnly: return "readOnly"; default: return "other" } }()
window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)

DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
    let v = ProcessInfo.processInfo.operatingSystemVersion
    // screencapture's -R is in screen points with the origin at the top-left of the main display.
    let frame = window.contentView!.convert(window.contentView!.bounds, to: nil)
    let screenRect = window.convertToScreen(frame)
    let mainH = NSScreen.screens.first?.frame.height ?? 0
    let x = Int(screenRect.minX), y = Int(mainH - screenRect.maxY), w = Int(screenRect.width), h = Int(screenRect.height)
    let region = "\(x),\(y),\(w),\(h)"

    // 1. the screenshot path
    let shot = NSTemporaryDirectory() + "ccs-probe-\(sharing).png"
    let shotStatus = run(["-x", "-R", region, shot])
    var shotRes = (fraction: -1.0, pixels: 0, size: "0x0")
    if let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: shot) as CFURL, nil), let img = CGImageSourceCreateImageAtIndex(src, 0, nil) { shotRes = magenta(in: img) }

    // 2. the recording path: two seconds of video of the same region, one frame read back at one second
    let mov = NSTemporaryDirectory() + "ccs-probe-\(sharing).mov"
    let recStatus = run(["-x", "-V", "2", "-R", region, mov])
    var recRes = (fraction: -1.0, pixels: 0, size: "0x0")
    if recStatus == 0 {
        let gen = AVAssetImageGenerator(asset: AVURLAsset(url: URL(fileURLWithPath: mov)))
        gen.requestedTimeToleranceBefore = .zero; gen.requestedTimeToleranceAfter = CMTime(seconds: 1, preferredTimescale: 600)
        if let cg = try? gen.copyCGImage(at: CMTime(seconds: 1, preferredTimescale: 600), actualTime: nil) { recRes = magenta(in: cg) }
    }

    let json = "{\"mode\":\"mac-probe\",\"macOS\":\"\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)\",\"sharingRequested\":\"\(sharing)\",\"sharingReadBack\":\"\(readBack)\","
        + "\"screenshot\":{\"status\":\(shotStatus),\"size\":\"\(shotRes.size)\",\"magentaFraction\":\(String(format: "%.3f", shotRes.fraction)),\"magentaPixels\":\(shotRes.pixels),\"verdict\":\"\(verdict(shotRes.fraction, shotRes.pixels))\"},"
        + "\"recording\":{\"status\":\(recStatus),\"size\":\"\(recRes.size)\",\"magentaFraction\":\(String(format: "%.3f", recRes.fraction)),\"magentaPixels\":\(recRes.pixels),\"verdict\":\"\(verdict(recRes.fraction, recRes.pixels))\"}}"
    print(json)
    try? json.write(toFile: out, atomically: true, encoding: .utf8)
    exit(0)
}
DispatchQueue.main.asyncAfter(deadline: .now() + 40) { print("{\"mode\":\"mac-probe\",\"verdict\":\"timed out\"}"); exit(1) }
app.run()
