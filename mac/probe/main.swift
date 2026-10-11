// mac/probe/main.swift — does macOS leave a window with sharingType .none out of a capture?
//   swiftc -O -framework AppKit -framework AVFoundation -framework ScreenCaptureKit mac/Capture.swift mac/probe/main.swift -o probe
//   ./probe none|readOnly [--out=probe.json]
// Draws the test pattern, waits a second, then measures three capture paths (mac/Capture.swift) and
// prints one JSON line. The readOnly run is the gate: if even that capture shows no pattern, this
// machine or this session cannot measure, and the result says so.
import AppKit

final class PatternView: NSView {
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) { Capture.drawTestPattern(in: bounds) }
}

let args = CommandLine.arguments
var sharing = "none"; var out = "probe.json"
for a in args.dropFirst() { if a.hasPrefix("--out=") { out = String(a.dropFirst(6)) } else if a == "none" || a == "readOnly" { sharing = a } }

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let window = NSWindow(contentRect: NSRect(x: 200, y: 200, width: 420, height: 320), styleMask: [.titled], backing: .buffered, defer: false)
window.title = "CCS probe"
let view = PatternView(frame: window.contentView!.bounds)
window.contentView = view
window.sharingType = sharing == "none" ? .none : .readOnly
let readBack: String = { switch window.sharingType { case .none: return "none"; case .readOnly: return "readOnly"; default: return "other" } }()
window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)

func finish(_ shot: CaptureResult, _ rec: CaptureResult, _ fw: CaptureResult) {
    let v = ProcessInfo.processInfo.operatingSystemVersion
    let json = "{\"mode\":\"mac-probe\",\"macOS\":\"\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)\",\"sharingRequested\":\"\(sharing)\",\"sharingReadBack\":\"\(readBack)\",\"screenshot\":\(shot.json),\"recording\":\(rec.json),\"framework\":\(fw.json)}"
    print(json)
    try? json.write(toFile: out, atomically: true, encoding: .utf8)
    exit(0)
}
DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
    let region = Capture.screenRegion(of: view)
    let shot = Capture.screenshot(region, tag: sharing)
    let rec = Capture.recording(region, seconds: 2, tag: sharing)
    if #available(macOS 14.0, *) {
        Task { let fw = await Capture.framework(region); DispatchQueue.main.async { finish(shot, rec, fw) } }
    } else {
        var fw = CaptureResult(); fw.verdict = "framework capture needs macOS 14"; finish(shot, rec, fw)
    }
}
DispatchQueue.main.asyncAfter(deadline: .now() + 60) { print("{\"mode\":\"mac-probe\",\"verdict\":\"timed out\"}"); exit(1) }
app.run()
