// mac/Capture.swift — how a Mac program measures whether its own window is left out of a capture.
// Shared by the probe (mac/probe/main.swift) and the viewer (mac/main.swift). Three paths, all the
// system's own: the screenshot tool, a short recording by the same tool, and, on macOS 14 and newer,
// a direct capture through the screen-capture framework (the path screen sharing and recorders use,
// reported to ignore the window's no-sharing setting on macOS 15 and newer). Each result is the count
// and fraction of magenta pixels of the test pattern found in the capture, and a verdict.
import AppKit
import AVFoundation
import ScreenCaptureKit

struct CaptureResult {
    var status: Int32 = -1
    var size = "0x0"
    var fraction = -1.0
    var pixels = 0
    var verdict = "not run"
    var json: String { "{\"status\":\(status),\"size\":\"\(size)\",\"magentaFraction\":\(String(format: "%.3f", fraction)),\"magentaPixels\":\(pixels),\"verdict\":\"\(verdict)\"}" }
}

enum Capture {
    /// The test pattern: magenta with white stripes. Drawn by the probe and by the viewer before it decrypts.
    static func drawTestPattern(in rect: NSRect) {
        NSColor(red: 1, green: 0, blue: 1, alpha: 1).setFill(); rect.fill()
        NSColor.white.setFill()
        var x = rect.minX
        while x < rect.maxX { NSRect(x: x, y: rect.minY, width: 12, height: rect.height).fill(); x += 48 }
    }

    static func magenta(in img: CGImage) -> (fraction: Double, pixels: Int, size: String) {
        let w = img.width, h = img.height
        var px = [UInt8](repeating: 0, count: w * h * 4)
        guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { return (-1, 0, "0x0") }
        ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
        var m = 0
        for p in 0..<(w * h) { let r = px[p * 4], g = px[p * 4 + 1], b = px[p * 4 + 2]; if r > 200 && g < 60 && b > 200 { m += 1 } }
        return (Double(m) / Double(w * h), m, "\(w)x\(h)")
    }
    static func verdict(_ fraction: Double, _ pixels: Int) -> String {
        if fraction < 0 { return "unreadable" }
        if fraction > 0.5 || pixels > 20000 { return "NOT excluded (the window is in the capture)" }
        if pixels < 50 { return "excluded (the window is not in the capture)" }
        return "partial"
    }
    static func fill(_ r: inout CaptureResult, _ m: (fraction: Double, pixels: Int, size: String)) { r.fraction = m.fraction; r.pixels = m.pixels; r.size = m.size; r.verdict = verdict(m.fraction, m.pixels) }

    private static func run(_ args: [String]) -> Int32 {
        let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture"); p.arguments = args
        do { try p.run(); p.waitUntilExit(); return p.terminationStatus } catch { return -2 }
    }

    /// The screen rectangle of a view, in the top-left-origin points screencapture and the capture framework use.
    static func screenRegion(of view: NSView) -> CGRect {
        guard let window = view.window else { return .zero }
        let frame = view.convert(view.bounds, to: nil)
        let screenRect = window.convertToScreen(frame)
        let mainH = NSScreen.screens.first?.frame.height ?? 0
        return CGRect(x: screenRect.minX, y: mainH - screenRect.maxY, width: screenRect.width, height: screenRect.height)
    }
    static func regionArg(_ r: CGRect) -> String { "\(Int(r.minX)),\(Int(r.minY)),\(Int(r.width)),\(Int(r.height))" }

    /// 1. The screenshot tool.
    static func screenshot(_ region: CGRect, tag: String) -> CaptureResult {
        var r = CaptureResult()
        let path = NSTemporaryDirectory() + "ccs-capture-\(tag).png"
        r.status = run(["-x", "-R", regionArg(region), path])
        if let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil), let img = CGImageSourceCreateImageAtIndex(src, 0, nil) { fill(&r, magenta(in: img)) }
        return r
    }
    /// 2. A recording by the same tool, one frame read back.
    static func recording(_ region: CGRect, seconds: Int, tag: String) -> CaptureResult {
        var r = CaptureResult()
        let path = NSTemporaryDirectory() + "ccs-capture-\(tag).mov"
        r.status = run(["-x", "-V", "\(seconds)", "-R", regionArg(region), path])
        if r.status == 0 {
            let gen = AVAssetImageGenerator(asset: AVURLAsset(url: URL(fileURLWithPath: path)))
            gen.requestedTimeToleranceBefore = .zero; gen.requestedTimeToleranceAfter = CMTime(seconds: 1, preferredTimescale: 600)
            if let cg = try? gen.copyCGImage(at: CMTime(seconds: Double(seconds) / 2, preferredTimescale: 600), actualTime: nil) { fill(&r, magenta(in: cg)) }
        }
        return r
    }
    /// 3. The screen-capture framework directly (macOS 14 and newer). Needs the Screen Recording permission.
    @available(macOS 14.0, *)
    static func framework(_ region: CGRect) async -> CaptureResult {
        var r = CaptureResult()
        do {
            let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
            guard let display = content.displays.first else { r.verdict = "no display"; return r }
            let filter = SCContentFilter(display: display, excludingWindows: [])
            let config = SCStreamConfiguration()
            config.sourceRect = region; config.width = Int(region.width); config.height = Int(region.height); config.showsCursor = false
            let img = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config)
            r.status = 0; fill(&r, magenta(in: img))
        } catch { r.status = -3; r.verdict = "framework capture failed: \(error.localizedDescription)" }
        return r
    }
}
