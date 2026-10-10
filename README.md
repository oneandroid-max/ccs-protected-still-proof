# The self-defending proof, second version (2026-10-10)

A public proof that a photo can be shown on any phone or computer so that the viewer sees a clean
picture while every copy that leaves the screen is traceable to that viewer and, for a casual
screenshot, worthless. Nothing here depends on a vendor: no DRM service, no licence server, no
library on the page. Plain browser code and one encrypted file.

- The page: https://oneandroid-max.github.io/ccs-protected-still-proof/ (the key goes after `#k=`; the PIN is given separately)
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

## What it cannot do

It cannot make a capture come out black. On a web page only the phone maker's own protected path does
that, and that path is always Apple's, Google's or Microsoft's. A screen recording captures both frames
and averaging them recovers the photo. A camera can photograph the screen. A developer console can read
the canvas. A device that limits animation is shown the marked still, and a screenshot captures it
cleanly. Every one of those copies still carries the viewer's mark. The promise is that a leak is
traceable and a casual capture is worthless, not that a capture is impossible.

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
