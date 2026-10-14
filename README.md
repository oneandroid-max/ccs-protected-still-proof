# Protected still — public proof of concept (2026-10-10)

A proof photo served as a Widevine-protected micro-video of a still frame, so a phone's screenshot
or screen recording of the photo area comes out black while the viewer sees a clean picture.
Keys from Google's public Widevine test key server; licences from Google's public test licence
proxy; player from a public CDN. No server of ours, no licence account, nothing connected to
the QuicLINKs application.

`drm/widevine/video.mp4` is encrypted: it is not a readable image, and no clear copy of the photo is
in this repository. Say the rest plainly: the key for this file is issued by Google's public test
key server from the content id that sits in the manifest, using the published test credentials from
the packager's tutorial, and the licence proxy binds the licence to no viewer. So this particular
file can be decrypted by anyone who reproduces the packager's key request. The proof is about the
phone's capture path, not key secrecy. Production packages with a private key and issues each
licence bound to the viewer's session, which is what makes the same page a real lock.

## Result (2026-10-10)

Verified on an Android phone over Chrome: security level `HW_SECURE_ALL`, the photo plays, a
screenshot of it comes out black, and a screen recording of the page shows the photo area black for
the whole clip while the rest of the page records normally. The first phone test failed with Shaka code 6007 because the page
added a custom header to the licence request and the public proxy's allowed-headers list does not
include it; the header was removed and the test passed on the next load.

## Open it on a phone

- The page: https://oneandroid-max.github.io/ccs-protected-still-proof/
- Google's own protected test clip, for comparison: https://oneandroid-max.github.io/ccs-protected-still-proof/?mode=google

The page is served with a ten-minute cache; after a change, add `?v=<anything new>` to the address
to force a fresh copy. A CDN view of the branch also works, behind a one-time "External Content
Notice": https://raw.githack.com/oneandroid-max/ccs-protected-still-proof/main/index.html

Wait for "Playing: yes", then take a screenshot with the phone's buttons and open it from the
gallery. On an Android phone with hardware protection the photo area is black. The readout on the
page says which security level the phone granted (`HW_SECURE_*` is hardware protection). On a
laptop browser or a phone with software-only protection the screenshot still captures the photo.

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
