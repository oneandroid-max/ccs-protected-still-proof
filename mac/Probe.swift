// mac/Probe.swift — does macOS still leave a window with sharingType .none out of a capture?
//   swiftc -O -framework AppKit apple/ProofCrypto.swift apple/ProofMark.swift mac/Probe.swift -o probe   (the shared files are not needed; listed for one build line)
//   ./probe --sharing none|readOnly [--out=probe.json]
// Draws a flat magenta window with white stripes, waits a second, captures its own screen area with the
// system tool (/usr/sbin/screencapture -x -R), reads the PNG back, and prints one JSON line: the macOS
// version, the sharing type read back, how many captured pixels are magenta, and the verdict. The
// readOnly run is the gate: if even that capture shows no magenta, this machine (or this runner session,
// or the missing Screen Recording permission) cannot measure, and the result says so.
import AppKit

final class StripeView: NSView {
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        NSColor(red: 1, green: 0, blue: 1, alpha: 1).setFill(); bounds.fill()
        NSColor.white.setFill()
        var x = bounds.minX
        while x < bounds.maxX { NSRect(x: x, y: bounds.minY, width: 12, height: bounds.height).fill(); x += 48 }
    }
}

func magentaFraction(_ path: String) -> (Double, Int, Int)? {
    guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil), let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { return nil }
    let w = img.width, h = img.height
    var px = [UInt8](repeating: 0, count: w * h * 4)
    guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { return nil }
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
    var magenta = 0
    for p in 0..<(w * h) { let r = px[p * 4], g = px[p * 4 + 1], b = px[p * 4 + 2]; if r > 200 && g < 60 && b > 200 { magenta += 1 } }
    return (Double(magenta) / Double(w * h), w, h)
}

let args = CommandLine.arguments
var sharing = "none"; var out = "probe.json"
for a in args.dropFirst() { if a.hasPrefix("--sharing=") { sharing = String(a.dropFirst(10)) } else if a == "--sharing" { } else if a.hasPrefix("--out=") { out = String(a.dropFirst(6)) } else if a == "none" || a == "readOnly" { sharing = a } }

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let window = NSWindow(contentRect: NSRect(x: 200, y: 200, width: 420, height: 320), styleMask: [.titled], backing: .buffered, defer: false)
window.title = "CCS probe"
window.contentView = StripeView(frame: window.contentView!.bounds)
window.sharingType = sharing == "none" ? .none : .readOnly
let readBack: String = { switch window.sharingType { case .none: return "none"; case .readOnly: return "readOnly"; case .readWrite: return "readWrite"; @unknown default: return "unknown" } }()
window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)

DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
    let v = ProcessInfo.processInfo.operatingSystemVersion
    // screencapture's -R is in screen points with the origin at the top-left of the main display.
    let frame = window.contentView!.convert(window.contentView!.bounds, to: nil)
    let screenRect = window.convertToScreen(frame)
    let mainH = NSScreen.screens.first?.frame.height ?? 0
    let x = Int(screenRect.minX), y = Int(mainH - screenRect.maxY), w = Int(screenRect.width), h = Int(screenRect.height)
    let path = NSTemporaryDirectory() + "ccs-probe-\(sharing).png"
    let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture"); p.arguments = ["-x", "-R", "\(x),\(y),\(w),\(h)", path]
    var captureStatus: Int32 = -1
    do { try p.run(); p.waitUntilExit(); captureStatus = p.terminationStatus } catch { captureStatus = -2 }
    var verdict = "no capture file"; var fraction = -1.0; var size = "0x0"
    if let (f, cw, ch) = magentaFraction(path) {
        fraction = f; size = "\(cw)x\(ch)"
        verdict = f > 0.5 ? "NOT excluded (the window is in the capture)" : (f < 0.05 ? "excluded (the window is not in the capture)" : "partial")
    }
    let json = "{\"mode\":\"mac-probe\",\"macOS\":\"\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)\",\"sharingRequested\":\"\(sharing)\",\"sharingReadBack\":\"\(readBack)\",\"screencaptureStatus\":\(captureStatus),\"captureSize\":\"\(size)\",\"magentaFraction\":\(String(format: "%.3f", fraction)),\"verdict\":\"\(verdict)\"}"
    print(json)
    try? json.write(toFile: out, atomically: true, encoding: .utf8)
    exit(0)
}
DispatchQueue.main.asyncAfter(deadline: .now() + 20) { print("{\"mode\":\"mac-probe\",\"verdict\":\"timed out\"}"); exit(1) }
app.run()
