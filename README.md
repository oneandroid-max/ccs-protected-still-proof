# The self-defending proof (2026-10-10)

A public proof of a process of our own, with no vendor in the chain, that blocks the stealing of a
photo on every format where a block is viable, and makes every other copy traceable. The goal and the
per-format status live in [PLAN.md](PLAN.md).

- **The Android viewer** (the block): https://github.com/oneandroid-max/ccs-protected-still-proof/releases/download/viewers/ccs-proof-viewer.apk — our own app; the window is flagged secure, so Android itself refuses to put it in a screenshot, a recording, a cast or the recent-apps thumbnail, while the photo on screen is drawn clean. Source in `android/`.
- **The Windows viewer** (the block, built and signed by a Windows runner; unsigned by any publisher): https://github.com/oneandroid-max/ccs-protected-still-proof/releases/download/viewers/ccs-proof-viewer-windows.exe — the window asks Windows to leave it out of every capture and measures its own screen area, including the Print Screen key, before and after decrypting. Source in `windows/`.
- **Route 1, the browser's own protected path — one link for every device** (a plain link, nothing installed; measured black on the owner's Android phone and Windows PC, and through Apple's FairPlay on the owner's iPhone): https://oneandroid-max.github.io/ccs-protected-still-proof/web/research/drm/?photo (the same address with no parameter opens the test site's one page, below, since 2026-10-13) — the page detects the browser and device by itself, names them at the top, and does what fits: the photo as a protected video the browser decrypts inside the device's protected path, shown only with protection the page accepts (hardware protection anywhere; software protection in Chrome and Edge on Windows and in Chrome on Android, where screenshots of it were measured black in Chrome and Edge on a Windows PC and in Chrome on an Android phone, and, not yet measured, in Edge on Android and in the other browsers on Windows and Android that the page reads as Chrome, apps' built-in browsers among them; not in Samsung Internet, Opera or Firefox); on an iPhone or iPad, only through Apple's FairPlay (screenshots of FairPlay video measured black on the owner's iPhone: 2026-10-12, Apple's test videos, played under Axinom's public test licence, and one of his own pictures on the test site, and 2026-10-13, the test site's combined view of all his pictures there, nine that day, the pictures and the view licensed by our own Axinom account; not yet measured: a screen recording, an iPad, other iOS versions; the test photo has no Apple form, so there it is held back and says so, while the test card and the site's pictures have one); on a Mac in Safari, while Apple's path is not yet measured there, Apple's test in the photo's place (Axinom's FairPlay test film, our FairPlay test card, and the card under our own Axinom account, beside the film unprotected as a control; none of it a CCS picture); anywhere else, the photo held back with where to open the link instead.
- **The Apple check** is now part of route 1 (above): its old address, https://oneandroid-max.github.io/ccs-protected-still-proof/web/research/apple/, forwards to the route-1 page's test card, never a picture.
- **The password-protected test site** (`site/`, GitHub only): https://oneandroid-max.github.io/ccs-protected-still-proof/site/ — one password opens the one page (since 2026-10-13): every ready picture in one protected view at the top (the combined view: every ready picture combined by the Action into ONE protected video, so a phone plays them all through a single protected decoder; tap a picture there to open it alone, in the route-1 viewer), and under it adding up to ten pictures of your own and deleting them; the combined view's old page, `site/all.html`, and the route-1 link with no parameter forward to it. Uploads are encrypted in the browser, a GitHub Action prepares them, and the protected files come back encrypted under the same password (Apple's form, which Safari must fetch by address, is encrypted under its own key instead, and the licence token that carries that key is sealed under the password), so this public repository never holds a readable picture. Set up once with `site/setup.html` (a fine-grained access token for this repository, sealed under the password in your browser; neither the password nor the token in clear ever enters the repository). **Apple:** with an Axinom evaluation key in the repository's secrets (`AXINOM_COM_KEY_ID`, `AXINOM_COM_KEY`), every picture also gets Apple's FairPlay form (`site-fairplay.yml` adds it to pictures prepared earlier): its files are encrypted under the picture's own key (Apple's 'cbcs' scheme, which leaves the frames' headers, sizes and the encoder's settings readable but not the picture), which only the picture's sealed licence token carries, renewed weekly; the token is sent only to the account's own FairPlay licence address (`site/axinom.json`, public by nature, the one the account's DRM Service page shows), recorded with each form, and a page sends it to no host that is not Axinom's; on an iPhone or iPad the pictures are shown only through their Apple form (switched on 2026-10-12, after screenshots of FairPlay video were measured black on the owner's iPhone; the same day one of his own pictures played there through its Apple form and came out black in the iPhone's screenshot, and on 2026-10-13 the one page's combined view of all his pictures, nine that day, did the same; not yet measured: a screen recording, an iPad, other iOS versions); on a Mac they stay held back until a screenshot there is measured black. `service/` holds the same site as a small stand-alone service for any host, with its own tests.
- **The door**: https://oneandroid-max.github.io/ccs-protected-still-proof/ — never draws the photo; hands the link's key (`#k=`) to the installed viewer and offers the installers.
- **The traceable page** (not a block; the research bench): https://oneandroid-max.github.io/ccs-protected-still-proof/trace/ (the key goes after `#k=`; the PIN is given separately)
- **The web research bench**: https://oneandroid-max.github.io/ccs-protected-still-proof/web/research/ — every candidate for a black capture on the web, tried one at a time.
- The first proof, vendor DRM (Widevine), kept for comparison on Android: https://oneandroid-max.github.io/ccs-protected-still-proof/widevine/

The page is served with a ten-minute cache; after a change, add `?v=<anything new>` to the address.

## What it does

1. **The photo exists only encrypted.** `photo.enc` is the screen-sized portrait under AES-256-GCM.
   The key is derived in the browser (PBKDF2-SHA256, 200,000 rounds) from the key in the link's
   `#k=` fragment, which browsers never send to any server, and the PIN the viewer types. Neither is in
   this repository. A wrong PIN fails the integrity check and shows nothing.
2. **The photo is drawn, never served.** The decrypted bytes go straight to a canvas; there is no image
   element to long-press or drag, and no file to save.
3. **A screenshot gets noise; the eye gets the photo.** Two frames, the photo plus and minus the same
   random noise, alternate every animation frame. The eye blends them; a screenshot catches one.
   The page measures its own frame rate for 1.5 seconds and, below 50 frames per second (an iPhone
   in Low Power Mode caps animation at 30), shows a still instead and says why. A reduced-motion
   setting, or the "Stop the alternation" button, does the same. The noise is zero-mean in every
   pixel, so no screen area changes its brightness between frames (no "flash" in the WCAG sense),
   and it changes brightness only, never hue.
4. **Every copy carries the viewer's mark.** An invisible ±3-of-255 pattern keyed to the link key, the
   PIN and the hour is added before the frames are made, so a screenshot of either frame, the still,
   and the share card all carry it. `tools/detect-mark.mjs` recovers it from a capture.
5. **The share the family is given** is a smaller, credited copy with the same mark, downloadable from
   the page: the easy, honest path.
6. **The readout shows only what the page measured** on the device in front of you.

## What the traceable page cannot do

The traceable page cannot make a capture come out black: the browser hands every frame to the device, and nothing
inside a page can refuse the device's own capture. The Android viewer below does refuse it, because an
installed app of ours can ask the system for that. A screen recording of the page captures both frames
and averaging them recovers the photo. A camera can photograph the screen. A developer console can read
the canvas. A device that limits animation is shown the marked still, and a screenshot captures it
cleanly. Every one of those copies still carries the viewer's mark. The promise is that a leak is
traceable and a casual capture is worthless, not that a capture is impossible.

## The Android viewer (`android/`)

Our own Java app on the Android framework and nothing else: no library, no vendor service, no network
call. It holds the same `photo.enc`, derives the same key from the link key and the PIN, draws the photo
clean, and adds the same invisible mark as the page.

- **The block.** The window carries the system's secure flag before its first frame. Android then leaves
  it out of screenshots, screen recordings, casting and the recent-apps thumbnail: a black box where the
  photo is. A long press on the photo offers nothing.
- **Fail closed.** The viewer decrypts only after the secure flag reads back from the window; the
  readout line "Capture refusal" is that reading, not a setting.
- **The readout** prints only what the phone measured: PIN accepted or refused, the flag, the Android
  version and device, the photo size, the mark id and hour, key and decrypt times, and on Android 14
  and newer the number of screenshot attempts the system reported.
- **The share card** (Android 10 and newer) saves a credited, marked 600-pixel copy to Pictures/CCS Proof
  and offers to share it.

Install: open the release link on the phone, allow installs from the browser when asked, install, open
"CCS Proof Viewer", paste the link key, type the PIN. The app also opens from the page's own link
(`https://oneandroid-max.github.io/ccs-protected-still-proof/#k=…`, the key is read from the link) and
from `ccsproof://open?k=…`.

Cross-check before the first install (`android/tools/CrossCheck.java` against `tools/cross-check.mjs`,
2026-10-10): both decrypt `photo.enc` to the same 130,950 bytes with the same SHA-256, derive the same
mark id and the same tile for the same key, PIN and hour, and both refuse a wrong PIN. The APK is built
and signed by `.github/workflows/android.yml` on a GitHub-hosted runner; the signing key in
`android/proof-signing.keystore` is a self-signed key for this sideloaded proof only.

The refusal is Android's own, asked for by our app. The key, the file, the mark, the viewer and the
fail-closed rule are ours. A camera pointed at the screen still photographs it, marked.

## Measured in a headless Chromium before publishing (2026-10-10, `tools/verify.mjs`)

| Check | Pixel ratio 1 | Pixel ratio 2 |
|---|---|---|
| Wrong PIN | refused | refused |
| Key derivation | 35 ms | 37 ms |
| Alternation rate | 61 per second | 57 per second |
| Screenshot of the moving photo vs the still | 21.7 dB PSNR (a wrecked copy) | 21.7 dB |
| Mark recovered from that screenshot | z = 57 (wrong PINs within ±1.2) | z = 121 (wrong within ±3.0) |
| Stopped still: screenshot vs still | 44.1 dB (clean) | 43.8 dB |
| Mark recovered from the still | z = 143 | z = 409 |
| Share card (600 px), mark recovered | z = 98 | z = 106 |

Reduced-motion setting: still mode, mark recovered at z = 409. A device capped at 30 frames per second:
still mode, the readout naming the measured 31 per second. Wrong keys can drift to about ±4 on a clean
still because every tile shares one period; the detector's verdict asks for a right-key score far above
that spread.

## Measured on the owner's own device (2026-10-10 22:33 UTC, Android, Chrome, device pixel ratio 2)

A screenshot taken with the device's buttons while the photo was alternating, sent back as a JPEG,
analysed by `tools/detect-mark.mjs` with a tile-offset search over a 1500×1700 crop of the photo area:

| Candidate | z-score |
|---|---|
| the viewer's PIN, hour 2026-10-10T22 | **224.35** (offset 8, 71) |
| the viewer's PIN, hour 21 and hour 23 | 3.11 and 3.86 |
| three wrong PINs, hour 22 | 6.25, 1.80, 2.22 |

The capture itself is the grainy, broken copy the design predicts (residual noise σ ≈ 20 of 255), and
it names its viewer and its hour. At scales 0.67, 0.8, 1.25 and 1.5 nothing is found, which shows the
upload arrived at true device pixels. With an offset search, wrong keys can score higher than on an
aligned image (the best of 16,384 offsets is kept), so the verdict compares the right key against that
spread; here the ratio is 36 to 1.

## Try it on a device

1. Open the link, type the PIN, wait for "Playing: yes". You see the photo with a fine shimmer.
2. Take a screenshot with the device's buttons and open it from the gallery: the photo area is a noisy,
   broken copy; the rest of the page is normal.
3. Start a screen recording, stop it, play it back: the frames flicker; an averaged recording recovers
   the photo, still marked.
4. Tap "Stop the alternation": the photo becomes a still; a screenshot captures it cleanly, still marked.
5. Download the share card.
Send the captures back; `tools/detect-mark.mjs` names the viewer and the hour from each.

| Device | On screen | A screenshot | A recording | Readout |
|---|---|---|---|---|
| iPhone Safari, normal | photo with shimmer | noisy, unusable | both frames, recombinable, marked | alternating, about 60 or 120 per second |
| iPhone Safari, Low Power Mode | marked still | clean, marked | clean, marked | still, about 30 per second |
| Android Chrome | photo with shimmer | noisy | both frames | alternating |
| Windows Edge, Chrome | photo with shimmer | noisy | both frames | alternating |
| Mac Safari, Chrome | photo with shimmer | noisy | both frames | alternating |

## Build and verify (tools run on the build machine only)

```
cd tools && npm install
node tools/build-photo.mjs --in=<portrait.jpg> --out=photo.enc          # prints the key and the PIN once
node tools/verify.mjs --secret=<key> --pin=<pin>                          # the measurements above
node tools/detect-mark.mjs --image=<capture.png> --secret=<key> --pin=<pin> --hour=YYYY-MM-DDTHH
```

`photo.enc` layout: `CCSP1`, version 1, PBKDF2 rounds (uint32), 16-byte salt, 12-byte IV, then the
AES-GCM ciphertext with its tag. Page parameters for testing: `?a=16..96` sets the noise amplitude
(default 48), `?fpscap=30` simulates a capped display, `?test=1` also shows the marked still.
