# Protected still — public proof of concept (2026-10-10)

A proof photo served as a Widevine-protected micro-video of a still frame, so a phone's screenshot
or screen recording of the photo area comes out black while the viewer sees a clean picture.
Keys from Google's public Widevine test key server; licences from Google's public test licence
proxy; player from a public CDN. No server of ours, no licence account, nothing connected to
the QuicLINKs application.

`drm/widevine/video.mp4` is encrypted: it is not a readable image. No clear copy of the photo is
in this repository.

## Open it on a phone

- The page: https://oneandroid-max.github.io/ccs-protected-still-proof/
- Google's own protected test clip, for comparison: https://oneandroid-max.github.io/ccs-protected-still-proof/?mode=google

Wait for "Playing: yes", then take a screenshot with the phone's buttons and open it from the
gallery. On an Android phone with hardware protection the photo area is black. The readout on the
page says which security level the phone granted (`HW_SECURE_*` is hardware protection).

iPhone: Safari uses FairPlay, not Widevine, so this page reports a licence error there. The same
packaging with an Apple FairPlay certificate gives the same black screenshot on iPhone; not built
here because it needs that certificate.

## What is in the repository

| File | What it is |
|---|---|
| `index.html` | The page: the protected still, the phone's protection readout, and the test steps. |
| `drm/widevine/manifest.mpd` | The DASH manifest naming the encrypted file and the Widevine key id. |
| `drm/widevine/video.mp4` | The 2-second still as H.264, encrypted (CENC) with a key issued by Google's test key server. |

Packaged with Shaka Packager v3.9.3; played with Shaka Player 5.2.10.
