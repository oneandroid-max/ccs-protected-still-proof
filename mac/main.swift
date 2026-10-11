// mac/main.swift — the Mac viewer of the self-defending proof, AppKit only, no library.
//
// The window asks for sharingType .none and reads it back. Then, before anything is decrypted, the
// viewer measures on this Mac whether that request is honoured: it draws a test pattern in the photo
// area and captures its own window three ways with the system's own tools (mac/Capture.swift: the
// screenshot tool, a one-second recording by the same tool, and the screen-capture framework directly).
// Fail closed: the photo is decrypted only if the read-back is .none and every capture that could be
// taken came back without the pattern. Measured on a GitHub macOS 26.6.2 runner (2026-10-11): the
// screenshot and the recording both left the window out. The readout prints only what this Mac measured.
import AppKit

final class PhotoView: NSView {
    var image: CGImage?
    var testPattern = false
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        NSColor.black.setFill(); bounds.fill()
        if testPattern { Capture.drawTestPattern(in: bounds); return }
        guard let img = image, let ctx = NSGraphicsContext.current?.cgContext else { return }
        let s = min(bounds.width / CGFloat(img.width), bounds.height / CGFloat(img.height))
        let w = CGFloat(img.width) * s, h = CGFloat(img.height) * s
        ctx.interpolationQuality = .high
        ctx.draw(img, in: CGRect(x: (bounds.width - w) / 2, y: (bounds.height - h) / 2, width: w, height: h))
    }
}

final class ViewerApp: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var measured = false, measuredExcluded = false
    var shotLine = "not measured yet", recLine = "not measured yet", fwLine = "not measured yet"
    let keyField = NSTextField(), pinField = NSTextField(), status = NSTextField(labelWithString: "Type the link key and the PIN, then Show."), readout = NSTextView()
    let photo = PhotoView()
    var pinState = "waiting", markIdText = "-", hourText = "-", timing = "-", keyFromLink: String?

    func applicationDidFinishLaunching(_ note: Notification) {
        let content = NSView(frame: NSRect(x: 0, y: 0, width: 640, height: 820))
        window = NSWindow(contentRect: content.frame, styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "CCS Proof Viewer"
        window.sharingType = .none        // the request, before the first frame
        window.contentView = content
        keyField.placeholderString = "Link key (the part after #k= in the link)"; keyField.frame = NSRect(x: 16, y: 780, width: 608, height: 24); keyField.stringValue = keyFromLink ?? ""
        pinField.placeholderString = "PIN"; pinField.frame = NSRect(x: 16, y: 748, width: 110, height: 24)
        let show = NSButton(title: "Show the photo", target: self, action: #selector(showPhoto)); show.frame = NSRect(x: 136, y: 744, width: 140, height: 32)
        status.frame = NSRect(x: 16, y: 716, width: 608, height: 24); status.lineBreakMode = .byTruncatingTail
        photo.frame = NSRect(x: 16, y: 232, width: 608, height: 476)
        let credit = NSTextField(labelWithString: "© Candid Color Systems · this view is marked to its viewer · the refusal is the system's own, asked for by this program; a camera pointed at the screen still photographs it, marked")
        credit.frame = NSRect(x: 16, y: 206, width: 608, height: 20); credit.font = .systemFont(ofSize: 10); credit.textColor = .secondaryLabelColor; credit.lineBreakMode = .byTruncatingTail
        let scroll = NSScrollView(frame: NSRect(x: 16, y: 16, width: 608, height: 184)); scroll.hasVerticalScroller = true; scroll.borderType = .bezelBorder
        readout.isEditable = false; readout.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular); readout.frame = scroll.contentView.bounds; readout.autoresizingMask = [.width]
        scroll.documentView = readout
        [keyField, pinField, show, status, photo, credit, scroll].forEach { content.addSubview($0) }
        refreshReadout()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        selfProbe()
    }

    /// Draws the test pattern in the photo area and captures this window three ways; decides whether the refusal holds here.
    func selfProbe() {
        photo.testPattern = true; photo.needsDisplay = true
        status.stringValue = "Measuring whether this Mac leaves the window out of a capture…"
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) {
            let region = Capture.screenRegion(of: self.photo)
            let shot = Capture.screenshot(region, tag: "viewer")
            let rec = Capture.recording(region, seconds: 1, tag: "viewer")
            let done: (CaptureResult) -> Void = { fw in
                self.shotLine = "\(shot.verdict) (\(shot.pixels) pattern px of \(shot.size))"
                self.recLine = "\(rec.verdict) (\(rec.pixels) pattern px of \(rec.size))"
                self.fwLine = fw.status == 0 ? "\(fw.verdict) (\(fw.pixels) pattern px of \(fw.size))" : fw.verdict
                let excluded: (CaptureResult) -> Bool = { $0.status == 0 && $0.verdict.hasPrefix("excluded") }
                // every capture that could be taken must have left the window out; a path that could not run is not a pass
                let taken = [shot, rec, fw].filter { $0.status == 0 }
                self.measuredExcluded = !taken.isEmpty && taken.allSatisfy(excluded) && shot.status == 0
                self.measured = true
                self.photo.testPattern = false; self.photo.needsDisplay = true
                self.status.stringValue = self.refusalHolds ? "This Mac left the window out of every capture it could take. Type the link key and the PIN, then Show." : "A capture of this window showed the test pattern, so the photo stays hidden here."
                self.refreshReadout()
            }
            if #available(macOS 14.0, *) { Task { let fw = await Capture.framework(region); DispatchQueue.main.async { done(fw) } } }
            else { var fw = CaptureResult(); fw.verdict = "framework capture needs macOS 14"; done(fw) }
        }
    }
    func application(_ application: NSApplication, open urls: [URL]) {
        if let u = urls.first, let f = u.fragment ?? URLComponents(url: u, resolvingAgainstBaseURL: false)?.query, let r = f.range(of: "k=") { keyFromLink = String(f[r.upperBound...].prefix { $0 != "&" }); keyField.stringValue = keyFromLink ?? "" }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    var macMajor: Int { ProcessInfo.processInfo.operatingSystemVersion.majorVersion }
    var sharingReadBack: String { switch window.sharingType { case .none: return "none"; case .readOnly: return "readOnly"; default: return "other" } }
    var refusalHolds: Bool { sharingReadBack == "none" && measured && measuredExcluded }

    @objc func showPhoto() {
        let secret = keyField.stringValue.trimmingCharacters(in: .whitespaces), pin = pinField.stringValue
        guard secret.count >= 8, pin.count == 6, pin.allSatisfy(\.isNumber) else { status.stringValue = "Enter the link key and the 6-digit PIN."; return }
        guard measured else { status.stringValue = "Still measuring; try again in a second."; return }
        guard refusalHolds else {
            pinState = "not tried: a capture of this window showed the test pattern"
            status.stringValue = "This Mac captured the window despite the no-sharing setting (measured at launch), so the photo stays hidden."
            refreshReadout(); return
        }
        status.stringValue = "Deriving the key and decrypting…"
        DispatchQueue.global(qos: .userInitiated).async {
            var img: CGImage? = nil; var state = "error"; var keyMs = 0, decMs = 0
            if let url = Bundle.main.url(forResource: "photo", withExtension: "enc"), let file = try? Data(contentsOf: url), let header = CCSP1Header.parse(file) {
                let t0 = Date()
                if let key = try? ProofCrypto.deriveKey(secret: secret, pin: pin, header: header) {
                    let t1 = Date()
                    do {
                        let plain = try ProofCrypto.decrypt(key: key, header: header); let t2 = Date()
                        keyMs = Int(t1.timeIntervalSince(t0) * 1000); decMs = Int(t2.timeIntervalSince(t1) * 1000)
                        if let src = CGImageSourceCreateWithData(plain as CFData, nil), let cg = CGImageSourceCreateImageAtIndex(src, 0, nil) {
                            let w = cg.width, h = cg.height; var px = [UInt8](repeating: 0, count: w * h * 4); let cs = CGColorSpaceCreateDeviceRGB()
                            px.withUnsafeMutableBytes { buf in CGContext(data: buf.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: cs, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)?.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h)) }
                            let hour = ProofMark.hourBucket(Date()); let seed = ProofMark.seed(secret: secret, pin: pin, hour: hour); let pattern = ProofMark.tilePattern(seed)
                            ProofMark.apply(&px, width: w, height: h, stride: w * 4, offR: 0, offG: 1, offB: 2, pattern: pattern)
                            img = px.withUnsafeMutableBytes { buf in CGContext(data: buf.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: cs, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)?.makeImage() }
                            DispatchQueue.main.async { self.markIdText = ProofMark.markId(seed); self.hourText = hour }
                            state = "accepted"
                        }
                    } catch ProofCryptoError.wrongKey { state = "refused" } catch { state = "error" }
                }
            }
            DispatchQueue.main.async {
                self.pinState = state; self.timing = state == "accepted" ? "key \(keyMs) ms, decrypt \(decMs) ms" : "-"
                self.photo.image = img; self.photo.needsDisplay = true
                self.status.stringValue = state == "accepted" ? "Showing the photo. Press Shift-Command-3 now." : (state == "refused" ? "Wrong PIN or link key: nothing to show." : "The photo could not be read.")
                self.refreshReadout()
            }
        }
    }

    func refreshReadout() {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "yyyy-MM-dd HH:mm:ss 'UTC'"
        readout.string = """
        PIN: \(pinState)
        Window sharing: requested none, read back \(sharingReadBack)
        macOS: \(v.majorVersion).\(v.minorVersion).\(v.patchVersion)   refusal honoured here: \(measured ? (refusalHolds ? "YES, measured at launch" : "NO, measured at launch") : "measuring")
        Self-capture, screenshot tool: \(shotLine)
        Self-capture, recording by the same tool: \(recLine)
        Self-capture, screen-capture framework: \(fwLine)
        Photo: \(photo.image == nil ? "not shown" : "drawn clean, \(photo.image!.width)x\(photo.image!.height) px")
        Viewer mark: \(markIdText) (hour \(hourText))
        Timing: \(timing)
        Device time: \(f.string(from: Date()))
        """
    }
}

let app = NSApplication.shared
let delegate = ViewerApp()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
