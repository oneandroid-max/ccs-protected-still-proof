// The protected pages' own decision lines, READ FROM THE HTML (never copied), run for many kinds of
// device and every kind of link: which protection is tried, and whether it would play the test card or a
// picture. The rules checked, on the route-1 page and on the two pages generated from it:
//   - every test link (each value the workflow guard accepts) plays the TEST CARD, and Apple's test the
//     card's form with Axinom's PUBLIC token, never a picture's;
//   - on Apple's engine (every iPhone or iPad browser, Safari on a Mac) nothing at all is tried for the
//     picture until FAIRPLAY_MEASURED holds a date for that platform, and then only Apple's own form,
//     with the picture's own form and token;
//   - nowhere else is the Apple form tried outside its test, and the switch changes nothing there.
// Also: the workflow guard refuses a link whose first parameter is not the safe one, or that names a
// second levels= or clip= (the page reads the first; the bypass a review found on 2026-10-11).
import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const read = (f) => fs.readFile(join(REPO, f), "utf8");
const START = "  const ua = navigator.userAgent;", END = "  // The platform and browser come from what the browser says about itself";

// the page's lines from the user agent to the order of attempts, as a function of the device and the link
function decide(html, measured) {
  const a = html.indexOf(START), b = html.indexOf(END);
  assert.ok(a > 0 && b > a && html.indexOf(START, a + 1) < 0 && html.indexOf(END, b + 1) < 0, "the page's decision block is found exactly once");
  let body = html.slice(a, b);
  if (measured) {
    const before = body;
    body = body.replace(/const FAIRPLAY_MEASURED = \{[^}]*\};/, `const FAIRPLAY_MEASURED = ${JSON.stringify(measured)};`);
    assert.notEqual(body, before, "the Apple switch is found");
  }
  return new Function("navigator", "location", "set", "CTX", body + "\nreturn { PLATFORM, APPLE, TEST, CARD, ORDER, CLIP, FAIRPLAY_OK };");
}

const IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)";
const MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)";
const CR = "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0";
// name: [user agent, touch points, Apple's engine?, platform, the order of attempts outside a test]
const DEVICES = {
  "iPhone Safari": [`${IOS} Version/17.5 Mobile/15E148 Safari/604.1`, 5, true, "iPhone/iPad"],
  "iPhone Chrome": [`${IOS} CriOS/126.0.6478.54 Mobile/15E148 Safari/604.1`, 5, true, "iPhone/iPad"],
  "iPhone in-app (Facebook)": [`${IOS} Mobile/15E148 [FBAN/FBIOS;FBAV/470.0]`, 5, true, "iPhone/iPad"],
  "iPad Safari": ["Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", 5, true, "iPhone/iPad"],
  "iPad asking for desktop sites": [`${MAC} Version/17.5 Safari/605.1.15`, 5, true, "iPhone/iPad"],
  "Mac Safari": [`${MAC} Version/17.5 Safari/605.1.15`, 0, true, "Mac"],
  "Mac app web view (no Safari/)": [MAC, 0, false, "Mac"],
  "Mac Chrome": [`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ${CR} Safari/537.36`, 0, false, "Mac"],
  "Mac Edge": [`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ${CR} Safari/537.36 Edg/126.0.0.0`, 0, false, "Mac"],
  "Mac Firefox": ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0", 0, false, "Mac"],
  "Windows Chrome": [`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${CR} Safari/537.36`, 0, false, "Windows"],
  "Windows Chrome, touch screen": [`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${CR} Safari/537.36`, 10, false, "Windows"],
  "Windows Edge": [`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ${CR} Safari/537.36 Edg/126.0.0.0`, 0, false, "Windows"],
  "Windows Firefox": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0", 0, false, "Windows"],
  "Android Chrome": [`Mozilla/5.0 (Linux; Android 14; Pixel 8) ${CR} Mobile Safari/537.36`, 5, false, "Android"],
  "Android Samsung Internet": [`Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36`, 5, false, "Android"],
  "Android Edge": [`Mozilla/5.0 (Linux; Android 14; Pixel 8) ${CR} Mobile Safari/537.36 EdgA/126.0.0.0`, 5, false, "Android"],
  "Linux Chrome": [`Mozilla/5.0 (X11; Linux x86_64) ${CR} Safari/537.36`, 0, false, "Linux"],
  "Linux Firefox": ["Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", 0, false, "Linux"],
  "ChromeOS": [`Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) ${CR} Safari/537.36`, 0, false, "ChromeOS"],
};
const SOFTWARE_OK = ["Windows Chrome", "Windows Chrome, touch screen", "Windows Edge", "Android Chrome", "Android Edge"];
const TESTS = { "?levels=software": ["widevine-software", "playready-software"], "?levels=clearkey": ["clearkey-card"], "?levels=fairplay": ["fairplay-apple"], "?levels=fairplay&v=9": ["fairplay-apple"] };
const OTHER = ["", "?clip=card", "?v=3", "?levels=x&levels=fairplay", "?clip=photo", "?levels=FAIRPLAY"];
const PICTURE = { manifest: "https://example.test/site/photos/ID/fp-0a1b2c3d/master.m3u8", token: "THE.PICTURES.OWN.TOKEN" };
const CTX = { content: "your picture: P", prKidGuid: "0", fairplay: PICTURE };

test("the pages' own lines, for 20 kinds of device and every kind of link: tests play only the card; Apple holds the picture back until measured; nothing else changes", async () => {
  const route1 = await read("web/research/drm/index.html");
  const publicToken = route1.match(/const AXINOM_PUBLIC_TOKEN = "([^"]+)"/)[1];
  const pages = { "route-1 page": route1, "site/view.html": await read("site/view.html"), "site/all.html": await read("site/all.html") };
  let runs = 0;
  for (const [pageName, html] of Object.entries(pages)) {
    const cardPath = pageName === "route-1 page" ? "card-fairplay/master.m3u8" : "../web/research/drm/card-fairplay/master.m3u8";
    for (const measured of [null, { "iPhone/iPad": "2026-10-11", "Mac": "" }, { "iPhone/iPad": "", "Mac": "2026-10-11" }]) {
      const fn = decide(html, measured);
      for (const [dev, [ua, touch, apple, platform]] of Object.entries(DEVICES)) {
        const at = (q) => { runs++; return fn({ userAgent: ua, maxTouchPoints: touch }, { search: q }, () => {}, CTX); };
        const what = (q) => `${pageName}, ${dev}, "${q}", Apple switch ${JSON.stringify(measured)}`;
        const plain = (q) => { // a link that is not a test
          const r = at(q);
          assert.equal(r.PLATFORM, platform, what(q)); assert.equal(r.APPLE, apple, what(q)); assert.equal(r.TEST, false, what(q));
          const ok = apple && !!(measured && measured[platform]);
          const want = apple ? (ok ? ["fairplay-apple"] : []) : SOFTWARE_OK.includes(dev) ? ["widevine-hardware", "widevine-software", "playready-hardware"] : ["widevine-hardware", "playready-hardware"];
          assert.deepEqual(r.ORDER, want, what(q));
          return r;
        };
        for (const [q, order] of Object.entries(TESTS)) {
          const r = at(q);
          assert.equal(r.TEST, true, what(q)); assert.equal(r.CARD, true, what(q)); assert.deepEqual(r.ORDER, order, what(q));
          assert.equal(r.CLIP.name, "the test card (not the photo)", what(q));
          assert.deepEqual(r.CLIP.fairplay, { manifest: cardPath, token: publicToken }, what(q) + ": the card's Apple form with Axinom's public token");
        }
        for (const q of OTHER) {
          const r = plain(q);
          const card = q === "?clip=card";
          assert.equal(r.CARD, card, what(q));
          if (card) assert.deepEqual(r.CLIP.fairplay, { manifest: cardPath, token: publicToken }, what(q));
          else assert.deepEqual(r.CLIP.fairplay, pageName === "route-1 page" ? null : PICTURE, what(q) + ": the picture's own Apple form");
          if (r.ORDER.includes("fairplay-apple")) assert.ok(apple && measured && measured[platform], what(q) + ": Apple's form only where measured");
        }
      }
    }
  }
  assert.ok(runs > 1500, `${runs} combinations run`);
});

// The guard, run in a copy of the repository's workflows and tools with one extra workflow, or with one
// file changed (edit: [relative path, function from its text to the new text])
async function guardWith(extra, edit, files = {}) {
  const d = await fs.mkdtemp(join(tmpdir(), "guard-"));
  await fs.cp(join(REPO, ".github"), join(d, ".github"), { recursive: true });
  await fs.cp(join(REPO, "tools"), join(d, "tools"), { recursive: true, filter: (src) => !src.includes("node_modules") });
  await fs.mkdir(join(d, "service"), { recursive: true }); await fs.copyFile(join(REPO, "service", "Dockerfile"), join(d, "service", "Dockerfile"));
  if (extra) await fs.writeFile(join(d, ".github", "workflows", "zz-extra.yml"), `name: x\non: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -sS "${extra}"\n`);
  if (edit) { const f = join(d, edit[0]); const before = await fs.readFile(f, "utf8"); const after = edit[1](before); assert.notEqual(after, before, "the edit changes " + edit[0]); await fs.writeFile(f, after); }
  for (const [rel, text] of Object.entries(files)) { await fs.mkdir(join(d, rel, ".."), { recursive: true }); await fs.writeFile(join(d, rel), text); }
  const r = spawnSync(process.execPath, [join(d, "tools", "check-workflow-links.mjs")], { cwd: d, encoding: "utf8" });
  await fs.rm(d, { recursive: true, force: true });
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}
// THE GUARD'S THIRD RULE (the sixth to eleventh reviews): a packager is brought in only by the pinned download, in a
// workflow or a Dockerfile, checked against its SHA-256 by the exact line after it; a workflow that downloads it lets
// no failure pass; every known download is counted. Every way around an earlier version that a review found is here,
// but those the guard is not meant to see (named in its comment; the run-time check in service/lib/packager-pin.mjs
// refuses what they bring wherever our programs run the packager: site/test/fairplay.test.mjs).
test("the guard refuses the obvious ways of bringing in a packager other than the pinned, checked download", async () => {
  const PIN = "https://github.com/shaka-project/shaka-packager/releases/download/v3.9.3/packager-linux-x64";
  const LATEST = "https://github.com/shaka-project/shaka-packager/releases/latest/download/packager-linux-x64";
  const MIRROR = "https://mirror.example.com/packager-linux-x64";
  const base = await guardWith(null);
  assert.equal(base.code, 0, base.out); assert.match(base.out, /all 9 shaka-packager downloads are the pinned release, checked by its SHA-256/);
  const ST = ".github/workflows/site-test.yml", DF = "service/Dockerfile", AT = "      - name: The generated view page is current";
  const step = (run) => (t) => t.replace(AT, `      - run: ${run}\n${AT}`);
  const uses = (action, more = "") => (t) => t.replace(AT, `      - uses: ${action}\n${more ? more + "\n" : ""}${AT}`);
  const afterRun = (text) => (t) => t.replace(/(\/usr\/local\/bin\/packager --version)\n/, `$1\n${text}\n`);
  const NAMED = /brings in a packager other than by the pinned download/, UNCHECKED = /the downloaded packager must be checked against its SHA-256 on the very next line, exactly/;
  const AFTER = /service\/Dockerfile:\d+: after the packager's check, this instruction may go on only with '&& …' lines/, LETS = /downloads shaka-packager and lets a failure pass/;
  const refused = [
    // another source or version, an image, an action, a container, a package
    [[".github/workflows/card-fairplay.yml", (t) => t.replace(PIN, LATEST)], NAMED],
    [[ST, step("gh release download v3.9.3 -R shaka-project/shaka-packager -p packager-linux-x64")], NAMED],
    [[ST, step("docker run --rm google/shaka-packager packager --version")], NAMED],
    [[ST, step("docker container run --rm google/shaka-packager packager --version")], NAMED],
    [[ST, step("podman run --rm google/shaka-packager packager --version")], NAMED],
    [[ST, step("docker run --rm ghcr.io/shaka-project/shaka-packager packager --version")], NAMED],
    [[ST, step("docker run --rm someone/shaka-packager packager --version")], NAMED],
    [[ST, step("npm install -g shaka-packager")], NAMED],
    [[ST, uses("some-org/setup-shaka-packager@v1")], NAMED],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    container: someone/shaka-packager:v3.9.3")], NAMED],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    container:\n      image: google/shaka-packager:v3.9.3")], NAMED],
    [[DF, (t) => t.replace(/RUN curl -sSL -o \/usr\/local\/bin\/packager [^\n]*\n  && echo [^\n]*\n  && chmod \+x \/usr\/local\/bin\/packager && \/usr\/local\/bin\/packager --version/, "COPY --from=google/shaka-packager:v3.9.3 /usr/bin/packager /usr/local/bin/packager")], NAMED],
    // the tenth review: what c4cc277 refused and the next two versions let through (no "shaka-packager" on the line)
    [[ST, step(`curl -sSL -o /usr/local/bin/packager ${MIRROR}`)], NAMED],
    [[ST, step("docker run --rm someorg/packager:v3 --version")], NAMED],
    [[ST, uses("someorg/setup-packager@v1")], NAMED],
    [[DF, afterRun(`RUN curl -sSL -o /usr/local/bin/packager ${MIRROR}`)], NAMED],
    // ... and what every version let through: an artifact or a cache of it, a copy, an archive, a package, a clone,
    // another fetcher, a Dockerfile ADD, a COPY from an image or from the build context
    [[ST, uses("actions/download-artifact@v4", "        with:\n          name: shaka-packager\n          path: /usr/local/bin")], NAMED],
    [[ST, uses("actions/cache@v4", "        with:\n          path: /usr/local/bin/packager\n          key: v3.9.3")], NAMED],
    [[ST, uses("actions/download-artifact@v4", "        with: { name: shaka-packager, path: /usr/local/bin }")], NAMED],
    [[ST, step("sudo cp /opt/tools/packager /usr/local/bin/packager")], NAMED],
    [[ST, step("tar -xzf tools.tgz -C /usr/local/bin packager")], NAMED],
    [[ST, step("pip install shaka-packager")], NAMED],
    [[ST, step("git clone --depth 1 https://github.com/shaka-project/shaka-packager")], NAMED],
    [[ST, step(`wget -q -O /usr/local/bin/packager ${PIN}`)], NAMED],
    [[DF, afterRun(`ADD ${PIN} /usr/local/bin/packager`)], NAMED],
    [[DF, afterRun("COPY --from=someorg/packager /usr/bin/packager /usr/local/bin/packager")], NAMED],
    [[DF, afterRun("COPY --from=someorg/tools:1 /usr/bin/packager /usr/local/bin/packager")], NAMED],
    [[DF, afterRun("COPY bin/packager /usr/local/bin/packager")], NAMED],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "FROM someorg/packager:v3 AS base")], NAMED],
    [[DF, afterRun("RUN --mount=type=bind,from=someorg/packager,target=/p /p/packager --version")], NAMED],
    // the eleventh review: a line that names shaka-packager itself, wherever it stands (an image on a continuation line,
    // in a variable, a build argument, a heredoc); a packager named in capitals
    [[ST, (t) => t.replace(AT, `      - run: |\n          docker run --rm \\\n            google/shaka-packager:latest packager --version\n${AT}`)], NAMED],
    [[ST, (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    env:\n      TOOL_IMAGE: google/shaka-packager:latest")], NAMED],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "ARG BASE=google/shaka-packager:latest\nFROM $1")], NAMED],
    [[ST, (t) => t.replace(AT, `      - run: |\n          docker build -t tools - <<'EOF'\n          FROM google/shaka-packager:latest\n          EOF\n${AT}`)], NAMED],
    [[ST, step(`curl -sSL -o /usr/local/bin/PACKAGER ${MIRROR}`)], NAMED],
    // a link after a quoted '#' on a code line (comments inside quotes are not comments)
    [[ST, step(`echo "a # b" && curl -sSL -o /tmp/p ${LATEST}`)], NAMED],
    // a curl that is not only the pinned download: another address beside it, another option, an output built by a command
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o /usr/local/bin/packager ${PIN} ${MIRROR}`)], NAMED],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -K /tmp/more -o /usr/local/bin/packager ${PIN}`)], NAMED],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o $(echo /usr/local/bin/packager) ${PIN}`)], NAMED],
    // ... and an output built by a command even with a check line to match it (only the plain-path rule refuses this)
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o $(pwd)/p ${PIN}`).replace(/(echo "7a3cf35a[0-9a-f]+  )\/usr\/local\/bin\/packager(" \| sha256sum -c - \|\| exit 1)/, "$1$(pwd)/p$2")], NAMED],
    // the check missing, changed, commented out, made harmless
    [[ST, (t) => t.replace(/\n\s+echo "7a3cf35a[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -[^\n]*/, "")], UNCHECKED],
    [[".github/workflows/drm-package.yml", (t) => t.replace("7a3cf35ad146fd78", "0000000000000000")], UNCHECKED],
    [[ST, (t) => t.replace(/(\n\s+)(echo "7a3cf35a[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -)/, "$1# $2")], UNCHECKED],
    [[".github/workflows/site-fairplay.yml", (t) => t.replace(/sha256sum -c - \|\| exit 1/, "sha256sum -c - || true")], UNCHECKED],
    [[".github/workflows/card-fairplay.yml", (t) => t.replace(/(\n\s+)(echo "7a3cf35a[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c - \|\| exit 1)/, "$1if false; then $2; fi")], UNCHECKED],
    [[DF, (t) => t.replace(/ \\\n  && echo "[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -/, "")], UNCHECKED],
    [[DF, (t) => t.replace(/\n  && echo ("[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c -) \\/, "\n#  && echo $1 \\")], UNCHECKED],
    // after the Dockerfile's check, only '&& …' lines with no ';', '||' or lone '&' (the tenth review: '&& … || true')
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  ; chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  | cat && chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  || chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("  && chmod +x /usr/local/bin/packager", "  &amp;&amp; chmod +x /usr/local/bin/packager")], AFTER],
    [[DF, (t) => t.replace("/usr/local/bin/packager --version", "/usr/local/bin/packager --version || true")], AFTER],
    [[DF, (t) => t.replace("/usr/local/bin/packager --version", "/usr/local/bin/packager --version; true")], AFTER],
    [[DF, (t) => t.replace("/usr/local/bin/packager --version", "/usr/local/bin/packager --version &")], AFTER],
    // a workflow that downloads it letting a failure pass, however written (the tenth review: the key quoted)
    [[".github/workflows/service-test.yml", (t) => t.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    continue-on-error: true")], /service-test\.yml:\d+: downloads shaka-packager and lets a failure pass/],
    [[ST, (t) => t.replace(AT, `      - continue-on-error: true\n        run: echo x\n${AT}`)], /site-test\.yml:\d+: downloads shaka-packager and lets a failure pass/],
    [[ST, (t) => t.replace(AT, `      - { name: x, run: echo x, continue-on-error: true }\n${AT}`)], /site-test\.yml:\d+: downloads shaka-packager and lets a failure pass/],
    [[ST, (t) => t.replace(AT, `      - "continue-on-error": true\n        run: echo x\n${AT}`)], LETS],
    [[ST, (t) => t.replace(AT, `      - 'continue-on-error': yes\n        run: echo x\n${AT}`)], LETS],
  ];
  for (const [edit, re] of refused) { const g = await guardWith(null, edit); assert.equal(g.code, 1, `${edit[0]} refused: ${g.out}`); assert.match(g.out, re); }
  // a new workflow fetching it another way; a download in an action, a script of any kind, another Dockerfile, a
  // Containerfile, a compose file anywhere, a Makefile, a package's own scripts
  const extra = await guardWith(LATEST);
  assert.equal(extra.code, 1, extra.out); assert.match(extra.out, /zz-extra\.yml:\d+: brings in a packager other than by the pinned download/);
  const down = (out) => `curl -sSL -o ${out} ${PIN}\nchmod +x ${out}\n`, OUTSIDE = (f) => new RegExp(`${f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}:\\d+: downloads shaka-packager outside a workflow or a Dockerfile`);
  for (const [file, text, re] of [
    [".github/actions/get-packager/action.yml", `name: get packager\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n        ${down("/usr/local/bin/packager").split("\n").join("\n        ")}`, OUTSIDE(".github/actions/get-packager/action.yml")],
    ["tools/get-packager.sh", `#!/bin/sh\n${down("/tmp/packager")}`, OUTSIDE("tools/get-packager.sh")],
    ["docker/Containerfile", `FROM debian:bookworm-slim\nRUN curl -sSL -o /usr/local/bin/packager ${PIN} \\\n  && chmod +x /usr/local/bin/packager\n`, /docker\/Containerfile:\d+: the downloaded packager must be checked/],
    ["docker/packager.dockerfile", `FROM debian:bookworm-slim\nRUN curl -sSL -o /usr/local/bin/packager ${PIN}\n`, /docker\/packager\.dockerfile:\d+: the downloaded packager must be checked/],
    ["tools/get-packager.bash", `#!/bin/bash\n${down("/tmp/packager")}`, OUTSIDE("tools/get-packager.bash")],
    ["tools/get-packager.ps1", "Invoke-WebRequest -Uri https://example.com/packager-win-x64.exe -OutFile packager.exe\n", /tools\/get-packager\.ps1:1: brings in a packager other than by the pinned download/],
    ["deploy/docker-compose.yml", "services:\n  pack:\n    image: someorg/packager:v3\n", /deploy\/docker-compose\.yml:3: brings in a packager other than by the pinned download/],
    ["Makefile", `packager:\n\t${down("bin/packager").split("\n")[0]}\n`, OUTSIDE("Makefile")],
    ["scripts/package.json", `{ "scripts": { "postinstall": "curl -sSL -o bin/packager ${PIN}" } }\n`, /scripts\/package\.json:1: brings in a packager other than by the pinned download/],
    // the eleventh review: every kind it claims to read, in either case (batch, module and Makefile names were not tested)
    ...["tools/get.bat", "tools/GET.BAT", "tools/get.cmd", "tools/get.psm1", "makefile", "GNUmakefile", "build/tools.mk", "MAKEFILE"].map((f) => [f, `${down("/tmp/packager").split("\n")[0]}\n`, OUTSIDE(f)]),
  ]) { const g = await guardWith(null, null, { [file]: text }); assert.equal(g.code, 1, `${file}: ${g.out}`); assert.match(g.out, re); }
  // a pinned, checked download in a workflow that DOWNLOADERS does not list: refused until it is listed
  const unlisted = await guardWith(null, null, { ".github/workflows/zz-new.yml": `name: x\non: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          curl -sSL -o /tmp/packager ${PIN}\n          echo "7a3cf35ad146fd7810b4ededab363c8a3e6121d1b2c8391f53863126186f9ee6  /tmp/packager" | sha256sum -c - || exit 1\n` });
  assert.equal(unlisted.code, 1, unlisted.out); assert.match(unlisted.out, /zz-new\.yml: a pinned download of shaka-packager that DOWNLOADERS in tools\/check-workflow-links\.mjs does not list/);
  // lock files are not read (a package named "packager" in one is not a download: the eleventh review)
  const lock = await guardWith(null, null, { "package-lock.json": `{ "packages": { "node_modules/@electron/packager": { "resolved": "https://registry.npmjs.org/@electron/packager/-/packager-18.3.6.tgz" } } }\n` });
  assert.equal(lock.code, 0, lock.out);
  // legitimate text: accepted (the tenth review: the version before refused the last five)
  const accepted = [
    [[ST, (t) => t.replace(AT, `      - name: Show which shaka-packager build (packager-linux-x64) is used\n        run: packager --version\n${AT}`)]],
    [[ST, (t) => t.replace(AT, `      # https://github.com/shaka-project/shaka-packager/releases/tag/v3.9.3\n${AT}`)]],
    [[ST, (t) => t.replace(AT, `      - name: x\n        continue-on-error: false\n        run: echo x\n${AT}`)]],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "FROM $1 AS packager")]],
    [[DF, (t) => t.replace(/ \\\n  && chmod \+x \/usr\/local\/bin\/packager && \/usr\/local\/bin\/packager --version/, "\nRUN chmod +x /usr/local/bin/packager && /usr/local/bin/packager --version")]],
    [[ST, step("echo hi # shaka-packager runs below; see https://github.com/shaka-project/shaka-packager")]],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -fsSL -o /usr/local/bin/packager ${PIN}`)]],
    [[ST, step('echo "shaka-packager $(packager --version)"')]],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, 'FROM $1\nLABEL description="ffmpeg and shaka-packager v3.9.3"')]],
    [[ST, (t) => t.replace(`curl -sSL -o /usr/local/bin/packager ${PIN}`, `curl -sSL -o /usr/local/bin/packager "${PIN}"`)]],
    [[DF, (t) => t.replace(/^FROM ([^\n]+)$/m, "FROM $1 AS packager") + "FROM node:22-bookworm-slim\nCOPY --from=packager /usr/local/bin/packager /usr/local/bin/packager\n"]],
  ];
  for (const [edit] of accepted) { const g = await guardWith(null, edit); assert.equal(g.code, 0, `${edit[0]} accepted: ${g.out}`); assert.match(g.out, /all 9 shaka-packager downloads/); }
  // a workflow that does NOT download it may let a step fail on (a measurement that goes on past one browser)
  assert.equal((await guardWith(null, [".github/workflows/live-check.yml", (t) => t.replace("    timeout-minutes: 5", "    timeout-minutes: 5\n    continue-on-error: true")])).code, 0);
  // a dangling Dockerfile link is no reason to fail
  const dangling = await (async () => { const d = await fs.mkdtemp(join(tmpdir(), "guard-")); try { await fs.cp(join(REPO, ".github"), join(d, ".github"), { recursive: true }); await fs.cp(join(REPO, "tools"), join(d, "tools"), { recursive: true }); await fs.mkdir(join(d, "service")); await fs.copyFile(join(REPO, "service", "Dockerfile"), join(d, "service", "Dockerfile")); await fs.symlink(join(d, "nowhere"), join(d, "Dockerfile.old")); const r = spawnSync(process.execPath, [join(d, "tools", "check-workflow-links.mjs")], { cwd: d, encoding: "utf8" }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; } finally { await fs.rm(d, { recursive: true, force: true }); } })();
  assert.equal(dangling.code, 0, dangling.out);
});

// The guard as CI runs it, in a git checkout (the tenth review: every test above runs it in a copy without .git, so a
// change that made it read nothing in a checkout passed them all)
test("the guard in a git checkout: what git ignores is left out, everything else read; a known download gone fails", async () => {
  const d = await fs.mkdtemp(join(tmpdir(), "guard-git-"));
  try {
    await fs.cp(join(REPO, ".github"), join(d, ".github"), { recursive: true });
    await fs.cp(join(REPO, "tools"), join(d, "tools"), { recursive: true, filter: (src) => !src.includes("node_modules") });
    await fs.mkdir(join(d, "service"), { recursive: true }); await fs.copyFile(join(REPO, "service", "Dockerfile"), join(d, "service", "Dockerfile"));
    await fs.writeFile(join(d, ".gitignore"), "ignored/\n");
    const git = (...a) => { const r = spawnSync("git", a, { cwd: d, encoding: "utf8" }); assert.equal(r.status, 0, r.stderr); };
    git("init", "-q"); git("add", "-A"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "x");
    const run = () => { const r = spawnSync(process.execPath, [join(d, "tools", "check-workflow-links.mjs")], { cwd: d, encoding: "utf8" }); return { code: r.status, out: (r.stdout || "") + (r.stderr || "") }; };
    const base = run(); assert.equal(base.code, 0, base.out); assert.match(base.out, /all 9 shaka-packager downloads/);
    const bad = "curl -sSL -o p https://mirror.example.com/packager-linux-x64\n";
    // in a folder git ignores: never committed, left out
    await fs.mkdir(join(d, "ignored"), { recursive: true }); await fs.writeFile(join(d, "ignored", "get.sh"), bad);
    const skipped = run(); assert.equal(skipped.code, 0, skipped.out);
    // ... unless it is committed there all the same (added by force): then it is the repository's, read, refused
    git("add", "-f", "ignored/get.sh"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "forced");
    const forced = run(); assert.equal(forced.code, 1, forced.out); assert.match(forced.out, /ignored\/get\.sh:1: brings in a packager other than by the pinned download/);
    git("rm", "-q", "--cached", "ignored/get.sh"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "unforced");
    assert.equal(run().code, 0, "taken out of the repository again: left out");
    // the same in a new file git does not ignore (not added yet), and once committed: read, refused
    await fs.mkdir(join(d, "scripts"), { recursive: true }); await fs.writeFile(join(d, "scripts", "get.sh"), bad);
    const fresh = run(); assert.equal(fresh.code, 1, fresh.out); assert.match(fresh.out, /scripts\/get\.sh:1: brings in a packager other than by the pinned download/);
    git("add", "-A"); git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "y");
    const committed = run(); assert.equal(committed.code, 1, committed.out); assert.match(committed.out, /scripts\/get\.sh:1:/);
    await fs.rm(join(d, "scripts"), { recursive: true });
    // a known download gone (the workflow changed, or the guard reading less than it should): refused
    const st = join(d, ".github", "workflows", "site-test.yml");
    await fs.writeFile(st, (await fs.readFile(st, "utf8")).replace(/\n\s+curl -sSL -o \/usr\/local\/bin\/packager [^\n]+\n\s+echo "[0-9a-f]+  \/usr\/local\/bin\/packager" \| sha256sum -c - \|\| exit 1[^\n]*/, ""));
    const less = run(); assert.equal(less.code, 1, less.out); assert.match(less.out, /\.github\/workflows\/site-test\.yml: expected 1 pinned download of shaka-packager, read 0/);
  } finally { await fs.rm(d, { recursive: true, force: true }); }
});

test("the guard accepts a link only when its FIRST parameter is a safe value and it names no other levels= or clip=", async () => {
  const B = "https://oneandroid-max.github.io/ccs-protected-still-proof/web/research/drm/";
  assert.equal((await guardWith(null)).code, 0, "the repository as it is passes");
  for (const ok of ["?levels=fairplay", "?levels=fairplay&v=3", "?clip=card&v=1", "?levels=clearkey"]) {
    const r = await guardWith(B + ok); assert.equal(r.code, 0, `${ok} is accepted: ${r.out}`);
  }
  for (const bad of ["?levels=x&levels=fairplay", "?levels=x&amp;levels=fairplay", "?v=1&clip=card", "?clip=card&levels=x", "?levels=fairplay&clip=photo", "?levels=FAIRPLAY", "", "?clip=cards"]) {
    const r = await guardWith(B + bad); assert.equal(r.code, 1, `${bad || "(no query)"} is refused`); assert.match(r.out, /does not ask for the test card/);
  }
});

test("the guard keeps the CI drive to a local copy: no secret, no write access, no capture, no other tool, and the drive pinned", async () => {
  const W = ".github/workflows/site-drive.yml";
  const cases = [
    [[W, (t) => t.replace("PLAYWRIGHT_PKG=", "SITE_PASSWORD=${{ secrets.SITE_PASSWORD }} PLAYWRIGHT_PKG=")], /the drive lost a safeguard: no secret at all/],
    [[W, (t) => t.replace("  contents: read", "  contents: write")], /the drive lost a safeguard: (read-only|no write access anywhere)/],
    [[W, (t) => t.replace("      - name: The drive", "      - uses: actions/upload-artifact@v4\n        with: { name: x, path: walk }\n      - name: The drive")], /the drive lost a safeguard: nothing uploaded and no screen capture/],
    [[W, (t) => t.replace("node tools/drive-site.mjs 2>&1", "node tools/walk-site.mjs 2>&1")], /the drive lost a safeguard: it runs no tool but the drive and this guard/],
    [[W, (t) => t.replace("        with: { persist-credentials: false }\n", "")], /the drive lost a safeguard: checkout leaves no token behind/],
    [["tools/drive-site.mjs", (t) => t + "\n// a change\n"], /tools\/drive-site\.mjs changed .* update PINNED/],
    // the rules read as they claim, not only through the pin (the third review's cases): a secret read with
    // brackets, a command or an action before the guard, a tool named with ./
    [[W, (t) => t.replace("PLAYWRIGHT_PKG=", "X=${{ secrets['A'] }} PLAYWRIGHT_PKG=")], /the drive lost a safeguard: no secret at all/],
    [[W, (t) => t.replace("      - name: The guard first", "      - run: echo first\n      - name: The guard first")], /the drive lost a safeguard: this guard runs first/],
    [[W, (t) => t.replace("      - name: The guard first", "      - uses: someone/action@v1\n      - name: The guard first")], /the drive lost a safeguard: this guard runs first/],
    [[W, (t) => t.replace("node tools/drive-site.mjs 2>&1", "node ./tools/walk-site.mjs 2>&1")], /the drive lost a safeguard: it runs no tool but the drive and this guard/],
    [[".github/workflows/site-walk.yml", (t) => t.replace("      - uses: actions/checkout@v4", "      - run: echo first\n      - uses: actions/checkout@v4")], /the walk lost a safeguard: the walk job runs this guard before anything else/],
  ];
  for (const [edit, re] of cases) { const r = await guardWith(null, edit); assert.equal(r.code, 1, `${edit[0]} edited: refused`); assert.match(r.out, re, r.out); }
});
