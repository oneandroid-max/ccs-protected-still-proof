// ios/ViewerViewController.swift — the probe and the viewer.
//
// The block on iPhone has no public API. The known way is to draw the content inside a secure text
// field's internal canvas view, which iOS leaves out of screenshots and recordings; Apple has never
// said whether that is supported, and one developer report says it fails on iOS 26. So:
//   - the content view is placed inside that canvas, found by class name ("CanvasView"); if no such
//     view exists, the app fails closed (no photo, the readout says why);
//   - while iOS reports the screen as captured (recording, mirroring: documented), the content is hidden;
//   - the full photo is drawn only on iOS major versions in MEASURED_BLACK_MAJORS, the list of versions
//     the owner has measured black on a real phone (empty until then). Elsewhere the probe rectangle is
//     shown instead: a flat colour with stripes, never the photo, so measuring a new version leaks nothing.
// The readout prints only what the device measured.
import UIKit

final class ViewerViewController: UIViewController {
    static let MEASURED_BLACK_MAJORS: [Int] = []     // filled from PLAN.md after a real-phone measurement

    var keyFromLink: String?
    let keyField = UITextField(), pinField = UITextField()
    private let showButton = UIButton(type: .system), statusLabel = UILabel(), readout = UITextView()
    private let secureField = UITextField()
    private let content = ProbeContentView()
    private var secureCanvasClass = "not found", pinState = "waiting", markIdText = "-", hourText = "-", timing = "-"
    private var screenshots = 0, drawnPhoto = false, pattern: [Int8]?

    static func key(from url: URL) -> String? {
        if let f = url.fragment, let r = f.range(of: "k=") { return String(f[r.upperBound...].prefix { $0 != "&" }) }
        if let q = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "k" })?.value { return q }
        return nil
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "CCS Proof Viewer"
        view.backgroundColor = .systemBackground
        let stack = UIStackView(); stack.axis = .vertical; stack.spacing = 10; stack.translatesAutoresizingMaskIntoConstraints = false
        let scroll = UIScrollView(); scroll.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll); scroll.addSubview(stack)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor), scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor), scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 12), stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -24),
            stack.leadingAnchor.constraint(equalTo: scroll.frameLayoutGuide.leadingAnchor, constant: 16), stack.trailingAnchor.constraint(equalTo: scroll.frameLayoutGuide.trailingAnchor, constant: -16),
        ])
        let lede = UILabel(); lede.numberOfLines = 0; lede.font = .preferredFont(forTextStyle: .footnote); lede.textColor = .secondaryLabel
        lede.text = "The photo is stored only encrypted inside this app. The key comes from the link and the PIN. The content is drawn inside the system's own secure text layer, which iOS has left out of screenshots and recordings; Apple does not promise it. The full photo is drawn only on iOS versions measured black on a real phone; elsewhere a test rectangle is shown instead. Every line below is measured on this phone."
        keyField.placeholder = "Link key (the part after #k= in the link)"; keyField.borderStyle = .roundedRect; keyField.autocapitalizationType = .none; keyField.autocorrectionType = .no; keyField.text = keyFromLink
        pinField.placeholder = "PIN (6 digits)"; pinField.borderStyle = .roundedRect; pinField.keyboardType = .numberPad
        showButton.setTitle("Show", for: .normal); showButton.addTarget(self, action: #selector(showPhoto), for: .touchUpInside)
        statusLabel.numberOfLines = 0; statusLabel.text = "Type the PIN, then Show."
        // The secure layer: the content lives inside the secure text field's canvas view.
        secureField.isSecureTextEntry = true; secureField.isUserInteractionEnabled = false; secureField.backgroundColor = .black
        secureField.translatesAutoresizingMaskIntoConstraints = false
        secureField.heightAnchor.constraint(equalTo: secureField.widthAnchor, multiplier: 4.0 / 3.0).isActive = true
        attachSecureCanvas()
        let credit = UILabel(); credit.numberOfLines = 0; credit.font = .preferredFont(forTextStyle: .caption1); credit.textColor = .secondaryLabel
        credit.text = "© Candid Color Systems · this view is marked to its viewer · the refusal is the device's own, asked for by our viewer; a camera pointed at the screen still photographs it, marked"
        readout.isEditable = false; readout.isScrollEnabled = false; readout.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular); readout.backgroundColor = .secondarySystemBackground
        let h = UILabel(); h.text = "WHAT THIS PHONE IS DOING (measured on this phone)"; h.font = .preferredFont(forTextStyle: .caption2); h.textColor = .secondaryLabel
        [lede, keyField, pinField, showButton, secureField, statusLabel, credit, h, readout].forEach { stack.addArrangedSubview($0) }
        NotificationCenter.default.addObserver(self, selector: #selector(captureChanged), name: UIScreen.capturedDidChangeNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(screenshotTaken), name: UIApplication.userDidTakeScreenshotNotification, object: nil)
        refreshReadout()
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        attachSecureCanvas(); captureChanged()
        if CommandLine.arguments.contains("--probe") { content.mode = .probe; content.setNeedsDisplay(); statusLabel.text = "Probe mode: the test rectangle is drawn inside the secure canvas." }
        refreshReadout()
    }
    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); attachSecureCanvas() }

    /// The secure text field's internal canvas view exists only once the field is laid out; it is searched
    /// by class name (a view whose class name contains "CanvasView"), never by a private API call.
    private func attachSecureCanvas() {
        guard content.superview == nil else { return }
        secureField.layoutIfNeeded()
        func find(_ v: UIView) -> UIView? { if String(describing: type(of: v)).contains("CanvasView") { return v }; for s in v.subviews { if let f = find(s) { return f } }; return nil }
        guard let canvas = find(secureField) else { return }
        secureCanvasClass = String(describing: type(of: canvas))
        content.frame = canvas.bounds; content.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        canvas.addSubview(content)
        refreshReadout()
    }

    private var isCaptured: Bool { view.window?.windowScene?.screen.isCaptured ?? false }
    @objc private func captureChanged() { content.isHidden = isCaptured; refreshReadout() }
    @objc private func screenshotTaken() { screenshots += 1; refreshReadout() }

    private static func readFile() -> Data? { Bundle.main.url(forResource: "photo", withExtension: "enc").flatMap { try? Data(contentsOf: $0) } }

    @objc private func showPhoto() {
        guard let secret = keyField.text?.trimmingCharacters(in: .whitespaces), secret.count >= 8, let pin = pinField.text, pin.count == 6, pin.allSatisfy(\.isNumber) else { statusLabel.text = "Enter the link key and the 6-digit PIN."; return }
        // Fail closed: the secure canvas must exist, the screen must not be captured, and this iOS major must be measured black.
        let major = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        guard secureCanvasClass != "not found" else { pinState = "not tried: no secure canvas on this iOS"; statusLabel.text = "This iOS has no secure canvas view, so nothing is drawn."; refreshReadout(); return }
        guard !isCaptured else { pinState = "not tried: the screen is being captured"; statusLabel.text = "The screen is being recorded or mirrored; nothing is drawn."; refreshReadout(); return }
        guard Self.MEASURED_BLACK_MAJORS.contains(major) else {
            pinState = "not tried: iOS \(major) not yet measured"; content.mode = .probe; content.setNeedsDisplay()
            statusLabel.text = "iOS \(major) is not yet measured on a real phone, so the test rectangle is shown instead of the photo. Take a screenshot and a recording of it: if both come out blank where the rectangle is, this version can be added to the measured list."
            refreshReadout(); return
        }
        showButton.isEnabled = false; statusLabel.text = "Deriving the key and decrypting…"
        DispatchQueue.global(qos: .userInitiated).async {
            var result: (UIImage?, String, Int, Int) = (nil, "error", 0, 0)
            if let file = Self.readFile(), let header = CCSP1Header.parse(file) {
                let t0 = Date()
                if let key = try? ProofCrypto.deriveKey(secret: secret, pin: pin, header: header) {
                    let t1 = Date()
                    do {
                        let plain = try ProofCrypto.decrypt(key: key, header: header)
                        let t2 = Date()
                        if let img = UIImage(data: plain) { result = (img, "accepted", Int(t1.timeIntervalSince(t0) * 1000), Int(t2.timeIntervalSince(t1) * 1000)) }
                    } catch ProofCryptoError.wrongKey { result = (nil, "refused", 0, 0) } catch { result = (nil, "error", 0, 0) }
                }
            }
            DispatchQueue.main.async { self.onDecrypted(secret: secret, pin: pin, image: result.0, state: result.1, keyMs: result.2, decMs: result.3) }
        }
    }

    private func onDecrypted(secret: String, pin: String, image: UIImage?, state: String, keyMs: Int, decMs: Int) {
        showButton.isEnabled = true; pinState = state
        guard let image = image, let cg = image.cgImage else { statusLabel.text = state == "refused" ? "Wrong PIN or link key: nothing to show." : "The photo could not be read."; refreshReadout(); return }
        hourText = ProofMark.hourBucket(Date())
        let seed = ProofMark.seed(secret: secret, pin: pin, hour: hourText); pattern = ProofMark.tilePattern(seed); markIdText = ProofMark.markId(seed)
        let w = cg.width, h = cg.height
        var px = [UInt8](repeating: 0, count: w * h * 4)
        let cs = CGColorSpaceCreateDeviceRGB()
        px.withUnsafeMutableBytes { buf in
            if let ctx = CGContext(data: buf.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: cs, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) { ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h)) }
        }
        ProofMark.apply(&px, width: w, height: h, stride: w * 4, offR: 0, offG: 1, offB: 2, pattern: pattern!)
        let marked: CGImage? = px.withUnsafeMutableBytes { buf in CGContext(data: buf.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: cs, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)?.makeImage() }
        content.photo = marked.map { UIImage(cgImage: $0) }; content.mode = .photo; content.setNeedsDisplay()
        drawnPhoto = true; timing = "key \(keyMs) ms, decrypt \(decMs) ms"
        statusLabel.text = "Showing the photo. Take a screenshot now."
        refreshReadout()
    }

    private func refreshReadout() {
        var u = utsname(); uname(&u)
        let model = withUnsafePointer(to: &u.machine) { $0.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) } }
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "yyyy-MM-dd HH:mm:ss 'UTC'"
        readout.text = """
        PIN: \(pinState)
        Secure canvas: \(secureCanvasClass)
        Screen captured (recording or mirroring): \(isCaptured ? "YES, content hidden" : "no")
        Screenshots reported by iOS: \(screenshots) (reported after the fact; iOS does not say what they contained)
        iOS: \(v.majorVersion).\(v.minorVersion).\(v.patchVersion)   measured black on this major: \(Self.MEASURED_BLACK_MAJORS.contains(v.majorVersion) ? "yes" : "NOT YET")
        Device: \(model)
        Content: \(drawnPhoto ? "the photo, drawn clean" : (content.mode == .probe ? "the test rectangle" : "nothing"))
        Viewer mark: \(markIdText) (hour \(hourText))
        Timing: \(timing)
        Device time: \(f.string(from: Date()))
        """
    }
}

/// The content inside the secure canvas: nothing, the probe rectangle, or the marked photo.
final class ProbeContentView: UIView {
    enum Mode { case none, probe, photo }
    var mode: Mode = .none
    var photo: UIImage?
    override init(frame: CGRect) { super.init(frame: frame); backgroundColor = .black; isOpaque = true; isUserInteractionEnabled = false }
    required init?(coder: NSCoder) { fatalError() }
    override func draw(_ rect: CGRect) {
        guard let ctx = UIGraphicsGetCurrentContext() else { return }
        ctx.setFillColor(UIColor.black.cgColor); ctx.fill(bounds)
        switch mode {
        case .none: return
        case .probe:
            ctx.setFillColor(UIColor(red: 1, green: 0, blue: 1, alpha: 1).cgColor); ctx.fill(bounds.insetBy(dx: 12, dy: 12))
            ctx.setFillColor(UIColor.white.cgColor)
            var x = bounds.minX + 12
            while x < bounds.maxX - 12 { ctx.fill(CGRect(x: x, y: bounds.minY + 12, width: 12, height: bounds.height - 24)); x += 48 }
        case .photo:
            guard let p = photo else { return }
            let s = min(bounds.width / p.size.width, bounds.height / p.size.height)
            let w = p.size.width * s, h = p.size.height * s
            p.draw(in: CGRect(x: (bounds.width - w) / 2, y: (bounds.height - h) / 2, width: w, height: h))
        }
    }
}
