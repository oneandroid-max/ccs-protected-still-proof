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
| Windows, our own program | The window asks Windows to exclude it from capture (`SetWindowDisplayAffinity`, Windows 10 version 2004 and newer). | Screenshot tools, recorders and screen share: the window left out. | Next. |
| Mac, our own program | The window's sharing type is set to none. | Screenshot and recording: the window left out. First launch warns that the program is not from the store. | Next. |
| iPhone, our own viewer | The photo is drawn inside the system's own secure text-entry layer, which iOS leaves out of captures; when a recording starts, iOS reports it and the viewer blanks the photo. | Screenshot and recording: blank today. Apple does not document the first part for this use and does not promise it holds across updates. Installing any iPhone app requires Apple's signature. | Next. The guarantee is an open track. |
| Web page, any browser | No in-house block exists today: the browser hands every frame to the device, and nothing inside a page can refuse the device's own capture. | The page as shown. The current page makes the capture noisy and marked. | Open track. The target is a black capture here too; every candidate is recorded below with its measured result. |
| A camera pointed at the screen | Nothing blocks it, on any device. | A photo of the screen, carrying the viewer's mark. | Stated limit. |

## Status log

- 2026-10-09: first proof, Widevine video, black on one Android phone; key derivable from the manifest; iPhone would need FairPlay. Ruled out.
- 2026-10-10: second proof, in-house: encrypted photo, canvas-only drawing, two-frame alternation, invisible mark. Measured on the owner's Android: the mark recovered from a screenshot (z = 224), the capture grainy but recognisable. Not a block.
- 2026-10-10: the goal restated as a block. Android viewer written (Java, no library), cross-checked against the page's code (same decrypted bytes, same mark), built and released by `.github/workflows/android.yml`.
- 2026-10-10 23:05 UTC: first runner build green in 43 s (run 38093728098). APK 149,398 bytes, SHA-256 `6cfb78f2008bf17dbb357fbf598a1a45097c7ada4d675908e22e0eb399d7f467`, signer `89d855e5…91bf3f` (the committed proof key), package `com.candidcolor.proofviewer`, minSdk 26, targetSdk 35, one permission (`DETECT_SCREEN_CAPTURE`), no icon yet. Release `android-v1`.
- 2026-10-10T23:06Z: install link and test steps sent to the owner. The result on the phone is not measured until the owner reports it.

## Open tracks

1. **Web, black capture without a vendor path.** No mechanism is known. Candidates are tried one at a time and each result is written here, pass or fail, with the command or screenshot that showed it.
2. **iPhone guarantee.** The secure-layer technique is measured on a real iPhone first; a documented route is searched for in parallel.
3. **Windows and Mac viewers.** Documented capture exclusion; built after the Android result is in.
4. **Mark recovery from a camera photo of the screen.** Expected, not measured.

## Testing the Android viewer

1. On the phone, open https://github.com/oneandroid-max/ccs-protected-still-proof/releases/latest/download/ccs-proof-viewer.apk and install it (allow installs from the browser when asked).
2. Open "CCS Proof Viewer", paste the link key, type the PIN, tap "Show the photo". The photo appears clean.
3. Take a screenshot. Start and stop a screen recording. Cast the screen if a TV is near. Open the recent-apps view. Long-press the photo.
4. Read the readout: "Capture refusal: ON" is the flag read back from the window; every other line is measured on the phone.
