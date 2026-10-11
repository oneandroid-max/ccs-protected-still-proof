# The plan — the self-defending proof

This file is the living plan for the proof. It is kept current with every push, so anyone can read
where the work stands without asking. Dates are UTC.

## The goal, in the owner's words (2026-10-10)

> "We are setting out to create and not copy nor use third party interventions, a process that will
> block users from stealing images, on all viable formats."

> "The image needs to appear undistorted but an attempt at copy of it via print screen or long press
> and save will give nothing in return."

The two places that do not yet give that result, a black capture on the web and a guarantee on
iPhone, are part of the target: *"we are going to get here, we're not there yet, but we are."*

## What is ruled out

- Every vendor protection path: FairPlay, Widevine, PlayReady and any DRM licence service. The first
  proof used Widevine and is kept at `widevine/` only as a comparison.
- A distorted or noisy picture for the viewer. The viewer sees the photo clean.
- A copy that is merely traceable. The second proof (the page at the root) makes a capture noisy and
  marked; it does not block, and blocking is the goal.

## What is ours in every format

The encrypted file (`photo.enc`, AES-256-GCM), the key that exists in no file (link secret plus PIN
through PBKDF2-SHA256), the viewer, the invisible mark naming the viewer and the hour, the readout
that prints only what the device measured, and the fail-closed rule: where the device cannot refuse a
capture, the full photo is never drawn.

The refusal itself can only come from the part of a device that draws the screen. Our viewers ask the
device for it; no outside service is in the chain.

## Formats

| Format | How the block works | What a capture gives | Status |
|---|---|---|---|
| Android, our own viewer (`android/`) | The window carries the system's secure flag before its first frame. The viewer decrypts only after the flag reads back from the window. | Screenshot, screen recording, cast and the recent-apps thumbnail: black where the photo is. A long press offers nothing. | Built, signed and released 2026-10-10 (`android-v1`). The result on a real phone is not yet measured. |
| Windows, our own program (`windows/`) | The window asks Windows to exclude it from capture (`SetWindowDisplayAffinity`, Windows 10 version 2004 and newer; older Windows: a black box). The program measures its own screen area three ways, including the real Print Screen key, and decrypts only when the capture does not contain the photo. | Screenshot tools, recorders and screen share: the window left out. Microsoft states it is not a security feature; a remote-desktop client or a virtual machine host captures from outside. | Next: being built. Not measured. |
| Mac, our own program (`mac/`) | The window's sharing type is set to none, and before decrypting the viewer measures on that Mac whether the setting is honoured: it draws a test pattern and captures its own window with the system's screenshot tool, a recording by the same tool, and the screen-capture framework directly. **Measured on a GitHub macOS 26.6.2 runner (2026-10-11 00:15 UTC, run 38097734426): the no-sharing window was left out of both the screenshot (0 pattern pixels) and the recording (0 pattern pixels), while the same window with read-only sharing was in both (99,759 and 94,015 pixels).** The framework path is measured on the next run. Reports that macOS 15+ ignores the setting for recordings and sharing (Apple bug FB21115847) stand against this runner measurement until the framework path is in. | Screenshot and recording by the system's tools: the window left out, measured. Third-party recorders and screen sharing: reported captured, measurement next. First launch needs Privacy & Security → Open Anyway. | Built; refusal measured on a runner for two of three paths; the viewer draws the photo only where its own launch measurement passes. No Mac in hand: not measured on a real Mac. |
| iPhone, our own viewer (`ios/`) | The photo is drawn inside the system's own secure text-entry layer, which iOS has left out of captures; when a recording starts, iOS reports it and the viewer blanks the photo. Apple has never answered whether the first part is supported; one developer report says it no longer works on iOS 26. The viewer draws the photo only on iOS versions measured black on a real phone (none yet). **Measured in the iOS 26.5 simulator on the runner (2026-10-11): the simulator's screenshot shows the secure-layer content (33.7% of the screen was the test rectangle), which is weak evidence either way, since the simulator is not a phone.** | Screenshot and recording: blank on the versions where it holds; unmeasured on iOS 26 on a phone. Installing any iPhone app requires Apple's signature. | Built, simulator-probed, unsigned package published. No iPhone in hand: not measured on a phone. |
| Web page, any browser | No in-house block exists today: the browser hands every frame to the device, and nothing inside a page can refuse the device's own capture. The root page becomes a door: it never draws the full photo and hands the link key to the installed viewer. | The door: nothing to capture. The traceable page (moving to `/trace/`): a noisy, marked copy. | Open track. The target is a black capture here too; every candidate is tried one at a time and recorded below with its screenshot. |
| A camera pointed at the screen | Nothing blocks it, on any device. | A photo of the screen, carrying the viewer's mark. | Stated limit. |

## Status log

- 2026-10-09: first proof, Widevine video, black on one Android phone; key derivable from the manifest; iPhone would need FairPlay. Ruled out.
- 2026-10-10: second proof, in-house: encrypted photo, canvas-only drawing, two-frame alternation, invisible mark. Measured on the owner's Android: the mark recovered from a screenshot (z = 224), the capture grainy but recognisable. Not a block.
- 2026-10-10: the goal restated as a block. Android viewer written (Java, no library), cross-checked against the page's code (same decrypted bytes, same mark), built and released by `.github/workflows/android.yml`.
- 2026-10-10 23:05 UTC: first runner build green in 43 s (run 38093728098). APK 149,398 bytes, SHA-256 `6cfb78f2008bf17dbb357fbf598a1a45097c7ada4d675908e22e0eb399d7f467`, signer `89d855e5…91bf3f` (the committed proof key), package `com.candidcolor.proofviewer`, minSdk 26, targetSdk 35, one permission (`DETECT_SCREEN_CAPTURE`), no icon yet. Release `android-v1`.
- 2026-10-10T23:06Z: install link and test steps sent to the owner. The result on the phone is not measured until the owner reports it.

- 2026-10-10T23:28Z: the plan for every remaining format was reviewed and approved: Windows next (the owner has the PC), the web root as the door, iPhone and Mac built and probed in CI and measured when a device exists. Facts that changed the table above: macOS 15+ ignores the no-sharing setting for recordings; the iPhone technique has one report of failing on iOS 26. The shared foundation landed: a committed test vector with a throwaway key (`tests/vectors/`), one canonical line every port must print (JavaScript and Java print it identically; `cross-check` workflow), and a rolling release `viewers` so every viewer's download address stays fixed (the per-build releases would have broken the APK link once a second viewer published).

- 2026-10-10T23:49Z: the web root is now the door (never fetches the photo, hands the `#k=` key to the installed viewer by `ccsproof://`, or `intent://` with an install fallback on Android Chrome; measured in headless Chromium: the only request the door makes is for itself). The traceable page moved unchanged to `/trace/` with a web-app manifest for research row 1; `web/research/` lists the seven candidates. The Windows viewer's first runner build failed on one missing header (`knownfolders.h`) and is pushed again. A measurement lesson from re-verifying the moved page: an element screenshot can sit one device pixel off the canvas grid, and at a fixed phase that turns a mark score of +409 into −30 (the box-blur high-pass anti-correlates a one-pixel shift); the detector's offset search finds the same mark at z = 487, so the verifier now searches the offset, as it already did for the owner's phone capture.

- 2026-10-10T23:56Z: **correction.** The previous line said the verifier "now searches the offset"; in that commit only the function's default changed and every call site still forced a fixed phase, so nothing searched. Caught by re-running the verification and reading the phase it printed (still 0,0). Fixed at the call sites; measured now on the moved page: moving frame z = 60 (pixel ratio 1) and 123 (ratio 2), stopped still z = 172 and 487, share card z = 99 and 107, wrong PINs within ±4.9, offset found at one CSS pixel (dy = 127 and 126 of 128). The Apple track is pushed: shared Swift crypto and mark with the same cross-check, the iPhone probe-and-viewer (the photo is drawn only on iOS majors measured black on a real phone, a list that is empty today), the Mac probe and the policy-A viewer, and one macOS workflow that probes the runner, screenshots the simulator and publishes the Mac zip and an unsigned iPhone package.

- 2026-10-11T00:14Z: Windows: the viewer compiled on the runner (308,224 bytes, SHA-256 `4a600dea…1314`, depending only on system DLLs: user32, gdi32, bcrypt, ole32, oleaut32, dwmapi, shell32, advapi32, kernel32); the C port printed the canonical line correctly, and the job failed only because the Windows checkout carried CRLF in the expected file (fixed: `.gitattributes` and a CR-stripping diff). The runner probe runs on the next build. Mac: the runner measured the system screenshot tool leaving the no-sharing window out on macOS 26.6.2 (table above); the probe now also records the window to measure the recording path. iPhone: one compile error (a selector name clashing with UIKit's `show`), fixed. The APK is also published on the site itself (`dist/`), because the release link's redirects led the owner's phone to open a different file twice. The owner's directive stands as the specification: a shared link, no download, the clean photo for the viewer, nothing in a screenshot, no third-party tools, every viable format. With our own code alone, "nothing" is reached inside the viewers; a page that holds the photo cannot reach it, and that is recorded here as the measured limit, not dressed up.

- 2026-10-11T00:20Z: web research rows 2, 3, 4 and 5 are built (`web/research/bench/` and `web/research/clearkey/`), rows 1 and 7 need only the traceable page. Headless Chromium in the sandbox ran candidates 2 and 5 without errors (fullscreen entered, pointer locked; WebGL drawing 79 frames in 2 s); candidate 3 needs a real tap; candidate 4 could not play there because that browser has no H.264. Every row waits for the owner's screenshot. Expected result on all seven: the photo is in the capture.

- 2026-10-11T00:24Z: the Apple workflow is green (run 38097734426, 7 minutes): the Swift port matches the vector; the Mac probe measured the runner's screenshot and recording tools both leaving the no-sharing window out (table above); the iPhone app built for the simulator, launched in probe mode, and its screenshot showed the rectangle (weak evidence); the unsigned iPhone package and the ad-hoc-signed Mac app are in the rolling release. The Mac viewer now decides by its own launch measurement instead of a version rule, and the probe adds the screen-capture framework path, the one the reports name.

## Open tracks

1. **Web, black capture without a vendor path.** No mechanism is known. Candidates are tried one at a time and each result is written here, pass or fail, with the command or screenshot that showed it.
2. **iPhone guarantee.** The secure-layer technique is measured on a real iPhone first; a documented route is searched for in parallel.
3. **Windows and Mac viewers.** Documented capture exclusion; built after the Android result is in.
4. **Mark recovery from a camera photo of the screen.** Expected, not measured.

## Testing the Android viewer

1. On the phone, open https://github.com/oneandroid-max/ccs-protected-still-proof/releases/download/viewers/ccs-proof-viewer.apk and install it (allow installs from the browser when asked).
2. Open "CCS Proof Viewer", paste the link key, type the PIN, tap "Show the photo". The photo appears clean.
3. Take a screenshot. Start and stop a screen recording. Cast the screen if a TV is near. Open the recent-apps view. Long-press the photo.
4. Read the readout: "Capture refusal: ON" is the flag read back from the window; every other line is measured on the phone.
