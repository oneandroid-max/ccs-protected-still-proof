/* viewer.c — the Windows viewer of the self-defending proof. Our own program on the Windows API and
 * nothing else: no library, no vendor service, no network call.
 *
 * The block: the window asks Windows to leave it out of every capture (SetWindowDisplayAffinity with
 * WDA_EXCLUDEFROMCAPTURE, Windows 10 version 2004 and newer; older Windows gives a black box) before its
 * first frame exists. The photo is drawn clean and undistorted. Fail closed: the photo is decrypted only
 * after the affinity reads back from the window AND a self-capture of a test pattern drawn in the photo
 * area comes back without the pattern. Every line of the readout is measured on this PC, including the
 * owner's own Print Screen key, read back from the clipboard.
 *
 *   ccs-proof-viewer-windows.exe [link-or-key] [--probe] [--no-affinity] [--out=probe.json]
 *
 * --probe draws the test pattern, runs the three self-captures (desktop BitBlt, PrintWindow, the Print
 * Screen key through the clipboard), writes one JSON line and exits. --no-affinity is the gate run: the
 * captures must then SHOW the pattern, or this machine cannot measure anything.
 *
 * Build (see .github/workflows/windows.yml):
 *   rc viewer.rc
 *   cl /W4 /O2 /DUNICODE /D_UNICODE viewer.c proofcore.c gcm.c viewer.res /Fe:ccs-proof-viewer-windows.exe
 *      /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib bcrypt.lib ole32.lib dwmapi.lib shell32.lib advapi32.lib
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include <ocidl.h>
#include <initguid.h>
#include <wincodec.h>
#include <dwmapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <shellapi.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proofcore.h"
#include "gcm.h"

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif
#ifndef PW_RENDERFULLCONTENT
#define PW_RENDERFULLCONTENT 0x00000002
#endif
#define IDR_PHOTO 101
#define ID_KEY 201
#define ID_PIN 202
#define ID_SHOW 203
#define ID_CARD 204
#define ID_STATUS 205
#define ID_READOUT 206
#define ID_CREDIT 207
#define WM_DECRYPTED (WM_APP + 1)
#define WM_RUNPROBE (WM_APP + 2)
#define WM_PRTSC_READ (WM_APP + 3)
#define TIMER_PROBE 1
#define TIMER_PRTSC 2

/* ---------------------------------------------------------------- state ---- */
static HINSTANCE g_hinst;
static HWND g_hwnd, g_key, g_pin, g_show, g_card, g_status, g_readout, g_credit;
static HFONT g_font, g_mono;
static int g_dpi = 96;
static BOOL g_probe = FALSE, g_noAffinity = FALSE;
static char g_outPath[MAX_PATH] = "probe.json";
static wchar_t g_keyFromLink[256];
static RECT g_photoRc;                 /* the photo area in client coordinates */
static HBITMAP g_stage; static uint8_t *g_stageBits; static int g_stageW, g_stageH;   /* what is on screen */
static HBITMAP g_photo; static uint8_t *g_photoBits; static int g_photoW, g_photoH;   /* the marked photo */
static int8_t *g_pattern; static char g_markId[9] = "-"; static char g_hour[16] = "-";
static BOOL g_testPattern = FALSE;     /* stage shows the test pattern (probe, or the gate before decrypt) */
/* measured facts */
static DWORD g_build; static BOOL g_composition, g_remote; static BOOL g_affinitySetOk; static DWORD g_affinityRead = 0xFFFFFFFF;
static char g_capBitBlt[64] = "not run", g_capPrintWindow[64] = "not run", g_capPrtSc[96] = "not run", g_lastUserPrtSc[96] = "not seen yet";
static char g_pinState[64] = "waiting", g_timing[64] = "-"; static int g_gateFailed = 0;
static wchar_t g_statusText[512];
static char g_secretUtf8[256], g_pinUtf8[16];

/* ------------------------------------------------------------ utilities ---- */
static int S(int logical) { return MulDiv(logical, g_dpi, 96); }
static void set_status(const wchar_t *s) { wcsncpy_s(g_statusText, 512, s, _TRUNCATE); if (g_status) SetWindowTextW(g_status, g_statusText); }

static DWORD os_build(void) {
  typedef LONG (WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  RtlGetVersionFn fn = nt ? (RtlGetVersionFn)(void *)GetProcAddress(nt, "RtlGetVersion") : NULL;
  RTL_OSVERSIONINFOW v; memset(&v, 0, sizeof v); v.dwOSVersionInfoSize = sizeof v;
  if (fn && fn(&v) == 0) return v.dwBuildNumber;
  return 0;
}
static void enable_dpi_awareness(void) {
  typedef BOOL (WINAPI *SetCtxFn)(DPI_AWARENESS_CONTEXT);
  HMODULE u = GetModuleHandleW(L"user32.dll");
  SetCtxFn fn = u ? (SetCtxFn)(void *)GetProcAddress(u, "SetProcessDpiAwarenessContext") : NULL;
  if (fn) fn(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
}
static int window_dpi(HWND h) {
  typedef UINT (WINAPI *GetDpiFn)(HWND);
  HMODULE u = GetModuleHandleW(L"user32.dll");
  GetDpiFn fn = u ? (GetDpiFn)(void *)GetProcAddress(u, "GetDpiForWindow") : NULL;
  return fn ? (int)fn(h) : 96;
}
static void utf8_of(const wchar_t *w, char *out, int outlen) { WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outlen, NULL, NULL); }

/* ---------------------------------------------------- DIBs and drawing ---- */
static HBITMAP make_dib(int w, int h, uint8_t **bits) {
  BITMAPINFO bi; HDC dc; HBITMAP b; void *p = NULL;
  memset(&bi, 0, sizeof bi);
  bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER); bi.bmiHeader.biWidth = w; bi.bmiHeader.biHeight = -h; bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
  dc = GetDC(NULL); b = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &p, NULL, 0); ReleaseDC(NULL, dc);
  *bits = (uint8_t *)p; return b;
}
/* The test pattern: a gradient with diagonal stripes, so a capture of it correlates strongly and a capture of anything else does not. */
static void draw_test_pattern(uint8_t *bits, int w, int h) {
  int x, y;
  for (y = 0; y < h; y++) for (x = 0; x < w; x++) {
    uint8_t *p = bits + ((size_t)y * w + x) * 4; int stripe = ((x + y) / 24) & 1;
    p[2] = (uint8_t)(255 * x / (w > 1 ? w - 1 : 1)); p[1] = stripe ? 40 : 200; p[0] = (uint8_t)(255 * y / (h > 1 ? h - 1 : 1)); p[3] = 255;
  }
}
static void render_stage(void) {
  HDC dc, sdc, pdc; HGDIOBJ o1, o2; int aw, ah, dw, dh, dx, dy;
  if (!g_stage) return;
  aw = g_stageW; ah = g_stageH;
  if (g_testPattern || !g_photo) { if (g_testPattern) draw_test_pattern(g_stageBits, aw, ah); else memset(g_stageBits, 0, (size_t)aw * ah * 4); return; }
  dc = GetDC(NULL); sdc = CreateCompatibleDC(dc); pdc = CreateCompatibleDC(dc);
  o1 = SelectObject(sdc, g_stage); o2 = SelectObject(pdc, g_photo);
  { RECT r = { 0, 0, aw, ah }; FillRect(sdc, &r, (HBRUSH)GetStockObject(BLACK_BRUSH)); }
  if ((long long)g_photoW * ah > (long long)g_photoH * aw) { dw = aw; dh = (int)((long long)aw * g_photoH / g_photoW); } else { dh = ah; dw = (int)((long long)ah * g_photoW / g_photoH); }
  dx = (aw - dw) / 2; dy = (ah - dh) / 2;
  SetStretchBltMode(sdc, HALFTONE); SetBrushOrgEx(sdc, 0, 0, NULL);
  StretchBlt(sdc, dx, dy, dw, dh, pdc, 0, 0, g_photoW, g_photoH, SRCCOPY);
  GdiFlush();
  SelectObject(sdc, o1); SelectObject(pdc, o2); DeleteDC(sdc); DeleteDC(pdc); ReleaseDC(NULL, dc);
}
static void ensure_stage(void) {
  int w = g_photoRc.right - g_photoRc.left, h = g_photoRc.bottom - g_photoRc.top;
  if (w < 8 || h < 8) return;
  if (g_stage && w == g_stageW && h == g_stageH) return;
  if (g_stage) DeleteObject(g_stage);
  g_stageW = w; g_stageH = h; g_stage = make_dib(w, h, &g_stageBits);
  render_stage();
}

/* ------------------------------------------------- capture comparison ---- */
typedef struct { double corr; double blackFrac; char verdict[32]; char note[64]; } capresult;
/* Normalized correlation of luminance between a captured BGRA buffer and the stage; the black fraction of the capture. */
static void compare_capture(const uint8_t *cap, int stride, capresult *r) {
  int n = g_stageW * g_stageH, x, y; double ma = 0, mb = 0, saa = 0, sbb = 0, sab = 0; int black = 0;
  double *la = (double *)malloc(sizeof(double) * n), *lb = (double *)malloc(sizeof(double) * n); int i = 0;
  for (y = 0; y < g_stageH; y++) for (x = 0; x < g_stageW; x++, i++) {
    const uint8_t *a = cap + (size_t)y * stride + (size_t)x * 4, *b = g_stageBits + ((size_t)y * g_stageW + x) * 4;
    la[i] = 0.114 * a[0] + 0.587 * a[1] + 0.299 * a[2]; lb[i] = 0.114 * b[0] + 0.587 * b[1] + 0.299 * b[2];
    if (a[0] < 8 && a[1] < 8 && a[2] < 8) black++;
    ma += la[i]; mb += lb[i];
  }
  ma /= n; mb /= n;
  for (i = 0; i < n; i++) { double da = la[i] - ma, db = lb[i] - mb; saa += da * da; sbb += db * db; sab += da * db; }
  r->corr = (saa > 1e-9 && sbb > 1e-9) ? sab / sqrt(saa * sbb) : 0.0;
  r->blackFrac = (double)black / n;
  if (r->corr > 0.9) strcpy_s(r->verdict, 32, "NOT excluded");
  else if (r->blackFrac > 0.9) strcpy_s(r->verdict, 32, "black");
  else strcpy_s(r->verdict, 32, "excluded");
  r->note[0] = 0;
  free(la); free(lb);
}
static void stage_screen_origin(POINT *pt) { pt->x = g_photoRc.left; pt->y = g_photoRc.top; ClientToScreen(g_hwnd, pt); }

/* (a) BitBlt from the desktop DC, the plain GDI screenshot path. */
static void capture_bitblt(capresult *r) {
  POINT pt; HDC screen, mem; HBITMAP bmp; uint8_t *bits; HGDIOBJ old;
  stage_screen_origin(&pt);
  screen = GetDC(NULL); mem = CreateCompatibleDC(screen); bmp = make_dib(g_stageW, g_stageH, &bits); old = SelectObject(mem, bmp);
  BitBlt(mem, 0, 0, g_stageW, g_stageH, screen, pt.x, pt.y, SRCCOPY | CAPTUREBLT); GdiFlush();
  compare_capture(bits, g_stageW * 4, r);
  SelectObject(mem, old); DeleteObject(bmp); DeleteDC(mem); ReleaseDC(NULL, screen);
}
/* (c) PrintWindow on our own handle: the window renders itself into a DC. */
static void capture_printwindow(capresult *r) {
  RECT wr; POINT origin = { 0, 0 }; HDC screen, mem; HBITMAP bmp; uint8_t *bits; HGDIOBJ old; int ww, wh, ox, oy;
  GetWindowRect(g_hwnd, &wr); ww = wr.right - wr.left; wh = wr.bottom - wr.top;
  ClientToScreen(g_hwnd, &origin); ox = origin.x - wr.left + g_photoRc.left; oy = origin.y - wr.top + g_photoRc.top;
  screen = GetDC(NULL); mem = CreateCompatibleDC(screen); bmp = make_dib(ww, wh, &bits); old = SelectObject(mem, bmp);
  if (!PrintWindow(g_hwnd, mem, PW_RENDERFULLCONTENT)) { strcpy_s(r->verdict, 32, "call failed"); r->corr = 0; r->blackFrac = 0; strcpy_s(r->note, 64, "PrintWindow returned 0"); }
  else { GdiFlush(); compare_capture(bits + (size_t)oy * ww * 4 + (size_t)ox * 4, ww * 4, r); }
  SelectObject(mem, old); DeleteObject(bmp); DeleteDC(mem); ReleaseDC(NULL, screen);
}
/* (b) The clipboard after a Print Screen: the full-screen DIB cropped to our screen area. 1 = measured, 0 = no image. */
static int capture_clipboard(capresult *r, char *sizeNote, int sizeNoteLen) {
  HANDLE h; BITMAPINFO *bi; uint8_t *src; int bw, bh, bpp, bottomUp, hdr, vx, vy, sx, sy, y; POINT pt; uint8_t *buf;
  if (!IsClipboardFormatAvailable(CF_DIB)) return 0;
  if (!OpenClipboard(g_hwnd)) return 0;
  h = GetClipboardData(CF_DIB);
  if (!h) { CloseClipboard(); return 0; }
  bi = (BITMAPINFO *)GlobalLock(h);
  bw = bi->bmiHeader.biWidth; bh = bi->bmiHeader.biHeight; bottomUp = bh > 0; if (bh < 0) bh = -bh; bpp = bi->bmiHeader.biBitCount;
  hdr = bi->bmiHeader.biSize + (bi->bmiHeader.biCompression == BI_BITFIELDS ? 12 : 0) + bi->bmiHeader.biClrUsed * 4;
  snprintf(sizeNote, sizeNoteLen, "%dx%d %dbpp", bw, bh, bpp);
  if (bpp != 32 && bpp != 24) { GlobalUnlock(h); CloseClipboard(); strcpy_s(r->verdict, 32, "unreadable"); snprintf(r->note, 64, "clipboard DIB is %d bpp", bpp); return 1; }
  src = (uint8_t *)bi + hdr;
  stage_screen_origin(&pt); vx = GetSystemMetrics(SM_XVIRTUALSCREEN); vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
  sx = pt.x - vx; sy = pt.y - vy;
  if (sx < 0 || sy < 0 || sx + g_stageW > bw || sy + g_stageH > bh) { GlobalUnlock(h); CloseClipboard(); strcpy_s(r->verdict, 32, "unreadable"); strcpy_s(r->note, 64, "window area outside the clipboard image"); return 1; }
  buf = (uint8_t *)malloc((size_t)g_stageW * g_stageH * 4);
  { int srcStride = ((bw * bpp + 31) / 32) * 4, x;
    for (y = 0; y < g_stageH; y++) {
      int row = bottomUp ? (bh - 1 - (sy + y)) : (sy + y);
      const uint8_t *s = src + (size_t)row * srcStride + (size_t)sx * (bpp / 8);
      uint8_t *d = buf + (size_t)y * g_stageW * 4;
      for (x = 0; x < g_stageW; x++) { d[x*4] = s[x*(bpp/8)]; d[x*4+1] = s[x*(bpp/8)+1]; d[x*4+2] = s[x*(bpp/8)+2]; d[x*4+3] = 255; }
    } }
  compare_capture(buf, g_stageW * 4, r);
  free(buf); GlobalUnlock(h); CloseClipboard();
  return 1;
}
static void press_print_screen(void) {
  if (OpenClipboard(g_hwnd)) { EmptyClipboard(); CloseClipboard(); }   /* so a stale image cannot be mistaken for this press */
  keybd_event(VK_SNAPSHOT, 0, 0, 0); keybd_event(VK_SNAPSHOT, 0, KEYEVENTF_KEYUP, 0);
}

/* ------------------------------------------------------------- readout ---- */
static void refresh_readout(void) {
  wchar_t buf[2048]; SYSTEMTIME st; GetSystemTime(&st);
  _snwprintf_s(buf, 2048, _TRUNCATE,
    L"Windows build %lu   composition: %s   remote session: %s   monitors: %d\r\n"
    L"Capture refusal: %s, read back %s\r\n"
    L"Self-capture, desktop BitBlt: %hs\r\n"
    L"Self-capture, PrintWindow: %hs\r\n"
    L"Self-capture, Print Screen key via clipboard: %hs\r\n"
    L"Your last Print Screen (clipboard): %hs\r\n"
    L"PIN: %hs   timing: %hs   photo: %s\r\n"
    L"Viewer mark: %hs (hour %hs)\r\n"
    L"Device time: %04d-%02d-%02d %02d:%02d:%02d UTC",
    (unsigned long)g_build, g_composition ? L"on" : L"off", g_remote ? L"yes" : L"no", GetSystemMetrics(SM_CMONITORS),
    g_noAffinity ? L"NOT requested (gate run)" : (g_affinitySetOk ? L"set" : L"SET FAILED"),
    g_affinityRead == WDA_EXCLUDEFROMCAPTURE ? L"EXCLUDEFROMCAPTURE (0x11)" : g_affinityRead == WDA_MONITOR ? L"MONITOR (0x1, black box)" : g_affinityRead == WDA_NONE ? L"NONE (0x0)" : L"unreadable",
    g_capBitBlt, g_capPrintWindow, g_capPrtSc, g_lastUserPrtSc,
    g_pinState, g_timing, g_photo ? L"drawn clean" : L"not shown",
    g_markId, g_hour, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
  if (g_photo) { wchar_t tail[64]; _snwprintf_s(tail, 64, _TRUNCATE, L" (%dx%d px)", g_photoW, g_photoH); wcscat_s(buf, 2048, tail); }
  if (g_readout) SetWindowTextW(g_readout, buf);
}
static void fmt_cap(char *dst, int len, const capresult *r) {
  if (r->note[0]) snprintf(dst, len, "%s (%s)", r->verdict, r->note);
  else snprintf(dst, len, "%s (correlation %.2f, black %.0f%%)", r->verdict, r->corr, r->blackFrac * 100.0);
}
/* Runs (a) and (c) now, presses Print Screen and reads the clipboard after a short wait. */
static void run_self_captures(void) {
  capresult r;
  capture_bitblt(&r); fmt_cap(g_capBitBlt, 64, &r);
  capture_printwindow(&r); fmt_cap(g_capPrintWindow, 64, &r);
  strcpy_s(g_capPrtSc, 96, "waiting for the key press");
  refresh_readout();
  press_print_screen();
  SetTimer(g_hwnd, TIMER_PRTSC, 900, NULL);
}
static void read_print_screen(int fromUser) {
  capresult r; char note[48]; char out[96];
  memset(&r, 0, sizeof r);
  if (capture_clipboard(&r, note, 48)) { if (r.note[0]) snprintf(out, 96, "%s (%s; %s)", r.verdict, r.note, note); else snprintf(out, 96, "%s (correlation %.2f, black %.0f%%; %s)", r.verdict, r.corr, r.blackFrac * 100.0, note); }
  else snprintf(out, 96, "no image on the clipboard (does Print Screen open Snipping Tool here?)");
  if (fromUser) strcpy_s(g_lastUserPrtSc, 96, out); else strcpy_s(g_capPrtSc, 96, out);
  refresh_readout();
}

/* ---------------------------------------------------------- probe JSON ---- */
static void write_probe_json(void) {
  char json[1400]; HANDLE f; DWORD n; wchar_t wpath[MAX_PATH];
  snprintf(json, sizeof json,
    "{\"mode\":\"probe\",\"affinityRequested\":%s,\"build\":%lu,\"composition\":%s,\"remoteSession\":%s,\"monitors\":%d,"
    "\"affinitySetOk\":%s,\"affinityReadBack\":%ld,\"stage\":[%d,%d],"
    "\"bitblt\":\"%s\",\"printWindow\":\"%s\",\"printScreenKey\":\"%s\"}\n",
    g_noAffinity ? "false" : "true", (unsigned long)g_build, g_composition ? "true" : "false", g_remote ? "true" : "false", GetSystemMetrics(SM_CMONITORS),
    g_affinitySetOk ? "true" : "false", (long)g_affinityRead, g_stageW, g_stageH, g_capBitBlt, g_capPrintWindow, g_capPrtSc);
  MultiByteToWideChar(CP_UTF8, 0, g_outPath, -1, wpath, MAX_PATH);
  f = CreateFileW(wpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f != INVALID_HANDLE_VALUE) { WriteFile(f, json, (DWORD)strlen(json), &n, NULL); CloseHandle(f); }
  if (AttachConsole(ATTACH_PARENT_PROCESS)) { HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE); if (out && out != INVALID_HANDLE_VALUE) WriteFile(out, json, (DWORD)strlen(json), &n, NULL); FreeConsole(); }
}

/* ------------------------------------------------------- the photo path ---- */
typedef struct { uint8_t *plain; size_t plainLen; int rc; DWORD keyMs, decMs; } decrypt_result;
static DWORD WINAPI decrypt_thread(LPVOID arg) {
  decrypt_result *res = (decrypt_result *)arg; HRSRC hr; HGLOBAL hg; const uint8_t *file; DWORD len; ccsp1_header h; uint8_t key[32]; DWORD t0, t1;
  res->rc = GCM_ERROR; res->plain = NULL;
  hr = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_PHOTO), RT_RCDATA); if (!hr) goto done;
  hg = LoadResource(NULL, hr); len = SizeofResource(NULL, hr); file = (const uint8_t *)LockResource(hg); if (!file || !len) goto done;
  if (!ccsp1_parse(file, len, &h)) goto done;
  t0 = GetTickCount(); ccsp1_derive_key(g_secretUtf8, g_pinUtf8, &h, key); t1 = GetTickCount(); res->keyMs = t1 - t0;
  res->plain = (uint8_t *)malloc(h.ciphertext_len);
  res->rc = gcm_decrypt(key, h.iv, h.ciphertext, h.ciphertext_len, res->plain, &res->plainLen);
  res->decMs = GetTickCount() - t1;
  SecureZeroMemory(key, 32);
  if (res->rc != GCM_OK) { free(res->plain); res->plain = NULL; }
done:
  PostMessageW(g_hwnd, WM_DECRYPTED, 0, (LPARAM)res);
  return 0;
}
/* JPEG bytes → BGRA via WIC. Returns 1 on success and fills a new DIB. */
static int decode_jpeg(const uint8_t *data, size_t len, HBITMAP *outBmp, uint8_t **outBits, int *w, int *h) {
  IWICImagingFactory *f = NULL; IWICStream *st = NULL; IWICBitmapDecoder *dec = NULL; IWICBitmapFrameDecode *fr = NULL; IWICFormatConverter *cv = NULL; UINT uw = 0, uh = 0; int ok = 0;
  if (FAILED(CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (void **)&f))) return 0;
  if (FAILED(IWICImagingFactory_CreateStream(f, &st))) goto done;
  if (FAILED(IWICStream_InitializeFromMemory(st, (WICInProcPointer)data, (DWORD)len))) goto done;
  if (FAILED(IWICImagingFactory_CreateDecoderFromStream(f, (IStream *)st, NULL, WICDecodeMetadataCacheOnDemand, &dec))) goto done;
  if (FAILED(IWICBitmapDecoder_GetFrame(dec, 0, &fr))) goto done;
  if (FAILED(IWICImagingFactory_CreateFormatConverter(f, &cv))) goto done;
  if (FAILED(IWICFormatConverter_Initialize(cv, (IWICBitmapSource *)fr, &GUID_WICPixelFormat32bppBGRA, WICBitmapDitherTypeNone, NULL, 0.0, WICBitmapPaletteTypeCustom))) goto done;
  if (FAILED(IWICFormatConverter_GetSize(cv, &uw, &uh)) || uw == 0 || uh == 0 || uw > 8192 || uh > 8192) goto done;
  *outBmp = make_dib((int)uw, (int)uh, outBits); if (!*outBmp) goto done;
  if (FAILED(IWICFormatConverter_CopyPixels(cv, NULL, uw * 4, uw * uh * 4, *outBits))) { DeleteObject(*outBmp); *outBmp = NULL; goto done; }
  *w = (int)uw; *h = (int)uh; ok = 1;
done:
  if (cv) IWICFormatConverter_Release(cv); if (fr) IWICBitmapFrameDecode_Release(fr); if (dec) IWICBitmapDecoder_Release(dec); if (st) IWICStream_Release(st); if (f) IWICImagingFactory_Release(f);
  return ok;
}
static void on_decrypted(decrypt_result *res) {
  EnableWindow(g_show, TRUE);
  if (res->rc == GCM_TAG_MISMATCH) { strcpy_s(g_pinState, 64, "refused"); set_status(L"Wrong PIN or link key: nothing to show."); refresh_readout(); free(res); return; }
  if (res->rc != GCM_OK || !res->plain) { strcpy_s(g_pinState, 64, "error"); set_status(L"The photo file could not be read."); refresh_readout(); free(res); return; }
  if (!decode_jpeg(res->plain, res->plainLen, &g_photo, &g_photoBits, &g_photoW, &g_photoH)) { set_status(L"The photo could not be decoded."); SecureZeroMemory(res->plain, res->plainLen); free(res->plain); free(res); return; }
  SecureZeroMemory(res->plain, res->plainLen); free(res->plain);
  { SYSTEMTIME st; uint8_t seed[32]; GetSystemTime(&st); snprintf(g_hour, 16, "%04d-%02d-%02dT%02d", st.wYear, st.wMonth, st.wDay, st.wHour);
    mark_seed(g_secretUtf8, g_pinUtf8, g_hour, seed); if (!g_pattern) g_pattern = (int8_t *)malloc(MARK_TILE * MARK_TILE); mark_tile_pattern(seed, g_pattern); mark_id(seed, g_markId); }
  mark_apply(g_photoBits, g_photoW, g_photoH, g_photoW * 4, 2, 1, 0, g_pattern);
  strcpy_s(g_pinState, 64, "accepted"); snprintf(g_timing, 64, "key %lu ms, decrypt %lu ms", (unsigned long)res->keyMs, (unsigned long)res->decMs);
  g_testPattern = FALSE; render_stage(); InvalidateRect(g_hwnd, &g_photoRc, FALSE); UpdateWindow(g_hwnd);
  set_status(L"Showing the photo. Press Print Screen now: the readout measures what the clipboard received.");
  EnableWindow(g_card, TRUE);
  free(res);
  { capresult r; capture_bitblt(&r); fmt_cap(g_capBitBlt, 64, &r); if (strcmp(r.verdict, "NOT excluded") == 0) { memset(g_stageBits, 0, (size_t)g_stageW * g_stageH * 4); InvalidateRect(g_hwnd, &g_photoRc, FALSE); set_status(L"A capture of this window CONTAINED the photo: the viewer blanked it."); }
    capture_printwindow(&r); fmt_cap(g_capPrintWindow, 64, &r); }
  refresh_readout();
}
/* The gate, then the decrypt thread. */
static void on_show(void) {
  wchar_t key[256], pin[16]; decrypt_result *res;
  GetWindowTextW(g_key, key, 256); GetWindowTextW(g_pin, pin, 16);
  if (wcslen(key) < 8 || wcslen(pin) != 6) { set_status(L"Enter the link key and the 6-digit PIN."); return; }
  utf8_of(key, g_secretUtf8, 256); utf8_of(pin, g_pinUtf8, 16);
  /* Fail closed: build, affinity set, affinity read back, and a self-capture of the test pattern. */
  g_gateFailed = 0;
  if (!g_affinitySetOk) g_gateFailed = 1;
  if (g_affinityRead != WDA_EXCLUDEFROMCAPTURE && g_affinityRead != WDA_MONITOR) g_gateFailed = 2;
  g_testPattern = TRUE; render_stage(); InvalidateRect(g_hwnd, &g_photoRc, FALSE); UpdateWindow(g_hwnd);
  { capresult r; capture_bitblt(&r); fmt_cap(g_capBitBlt, 64, &r); if (strcmp(r.verdict, "NOT excluded") == 0) g_gateFailed = 3;
    capture_printwindow(&r); fmt_cap(g_capPrintWindow, 64, &r); }
  if (g_gateFailed) {
    g_testPattern = FALSE; render_stage(); InvalidateRect(g_hwnd, &g_photoRc, FALSE);
    strcpy_s(g_pinState, 64, g_gateFailed == 1 ? "not tried: affinity call failed" : g_gateFailed == 2 ? "not tried: affinity not read back" : "not tried: a capture showed the test pattern");
    set_status(L"This window cannot refuse capture here, so the photo stays hidden.");
    refresh_readout(); return;
  }
  EnableWindow(g_show, FALSE); set_status(L"Deriving the key and decrypting…");
  res = (decrypt_result *)calloc(1, sizeof *res);
  CloseHandle(CreateThread(NULL, 0, decrypt_thread, res, 0, NULL));
}

/* ------------------------------------------------------- the share card ---- */
static int write_jpeg(const wchar_t *path, const uint8_t *bgra, int w, int h) {
  IWICImagingFactory *f = NULL; IWICStream *st = NULL; IWICBitmapEncoder *enc = NULL; IWICBitmapFrameEncode *fr = NULL; IPropertyBag2 *props = NULL; int ok = 0;
  WICPixelFormatGUID fmt = GUID_WICPixelFormat24bppBGR; uint8_t *bgr; int x, y;
  if (FAILED(CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (void **)&f))) return 0;
  if (FAILED(IWICImagingFactory_CreateStream(f, &st)) || FAILED(IWICStream_InitializeFromFilename(st, path, GENERIC_WRITE))) goto done;
  if (FAILED(IWICImagingFactory_CreateEncoder(f, &GUID_ContainerFormatJpeg, NULL, &enc))) goto done;
  if (FAILED(IWICBitmapEncoder_Initialize(enc, (IStream *)st, WICBitmapEncoderNoCache))) goto done;
  if (FAILED(IWICBitmapEncoder_CreateNewFrame(enc, &fr, &props))) goto done;
  { PROPBAG2 opt; VARIANT v; memset(&opt, 0, sizeof opt); opt.pstrName = L"ImageQuality"; VariantInit(&v); v.vt = VT_R4; v.fltVal = 0.9f; IPropertyBag2_Write(props, 1, &opt, &v); }
  if (FAILED(IWICBitmapFrameEncode_Initialize(fr, props))) goto done;
  if (FAILED(IWICBitmapFrameEncode_SetSize(fr, (UINT)w, (UINT)h)) || FAILED(IWICBitmapFrameEncode_SetPixelFormat(fr, &fmt))) goto done;
  bgr = (uint8_t *)malloc((size_t)w * h * 3);
  for (y = 0; y < h; y++) for (x = 0; x < w; x++) { const uint8_t *s = bgra + ((size_t)y * w + x) * 4; uint8_t *d = bgr + ((size_t)y * w + x) * 3; d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; }
  if (SUCCEEDED(IWICBitmapFrameEncode_WritePixels(fr, (UINT)h, (UINT)(w * 3), (UINT)(w * h * 3), bgr)) && SUCCEEDED(IWICBitmapFrameEncode_Commit(fr)) && SUCCEEDED(IWICBitmapEncoder_Commit(enc))) ok = 1;
  free(bgr);
done:
  if (props) IPropertyBag2_Release(props); if (fr) IWICBitmapFrameEncode_Release(fr); if (enc) IWICBitmapEncoder_Release(enc); if (st) IWICStream_Release(st); if (f) IWICImagingFactory_Release(f);
  return ok;
}
static void save_share_card(void) {
  const int cw = 600, band = 64; int ch; HBITMAP card; uint8_t *bits; HDC dc, cdc, pdc; HGDIOBJ o1, o2; RECT r; HFONT f1, f2; HGDIOBJ of;
  PWSTR pictures = NULL; wchar_t dir[MAX_PATH], path[MAX_PATH], msg[600];
  if (!g_photo || !g_pattern) return;
  ch = (int)((long long)cw * g_photoH / g_photoW);
  card = make_dib(cw, ch + band, &bits);
  dc = GetDC(NULL); cdc = CreateCompatibleDC(dc); pdc = CreateCompatibleDC(dc); o1 = SelectObject(cdc, card); o2 = SelectObject(pdc, g_photo);
  SetStretchBltMode(cdc, HALFTONE); SetBrushOrgEx(cdc, 0, 0, NULL);
  StretchBlt(cdc, 0, 0, cw, ch, pdc, 0, 0, g_photoW, g_photoH, SRCCOPY); GdiFlush();
  mark_apply(bits, cw, ch, cw * 4, 2, 1, 0, g_pattern);       /* the card carries the viewer's mark at its own size */
  { HBRUSH navy = CreateSolidBrush(RGB(1, 27, 81)); r.left = 0; r.top = ch; r.right = cw; r.bottom = ch + band; FillRect(cdc, &r, navy); DeleteObject(navy); }
  SetBkMode(cdc, TRANSPARENT); SetTextColor(cdc, RGB(255, 255, 255));
  f1 = CreateFontW(-18, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
  f2 = CreateFontW(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
  of = SelectObject(cdc, f1); TextOutW(cdc, 16, ch + 10, L"Candid Color Systems", 20);
  SelectObject(cdc, f2); { const wchar_t *t = L"Shared with the family \x00b7 gallery: (your gallery link here) \x00b7 marked to its viewer"; TextOutW(cdc, 16, ch + 36, t, (int)wcslen(t)); }
  SelectObject(cdc, of); DeleteObject(f1); DeleteObject(f2); GdiFlush();
  SelectObject(cdc, o1); SelectObject(pdc, o2); DeleteDC(cdc); DeleteDC(pdc); ReleaseDC(NULL, dc);
  if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_Pictures, 0, NULL, &pictures))) { _snwprintf_s(dir, MAX_PATH, _TRUNCATE, L"%s\\CCS Proof", pictures); CoTaskMemFree(pictures); }
  else wcscpy_s(dir, MAX_PATH, L".");
  CreateDirectoryW(dir, NULL);
  _snwprintf_s(path, MAX_PATH, _TRUNCATE, L"%s\\ccs-share-card-%hs.jpg", dir, g_markId);
  if (write_jpeg(path, bits, cw, ch + band)) { _snwprintf_s(msg, 600, _TRUNCATE, L"Share card saved: %s", path); set_status(msg); }
  else set_status(L"Could not write the share card.");
  DeleteObject(card);
}

/* ----------------------------------------------------- ccsproof:// link ---- */
static void register_url_scheme(void) {
  HKEY k; wchar_t exe[MAX_PATH], cmd[MAX_PATH + 16]; const wchar_t *name = L"URL:CCS Proof Viewer";
  GetModuleFileNameW(NULL, exe, MAX_PATH);
  if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ccsproof", 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS) return;
  RegSetValueExW(k, NULL, 0, REG_SZ, (const BYTE *)name, (DWORD)((wcslen(name) + 1) * sizeof(wchar_t)));
  RegSetValueExW(k, L"URL Protocol", 0, REG_SZ, (const BYTE *)L"", sizeof(wchar_t));
  RegCloseKey(k);
  if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ccsproof\\shell\\open\\command", 0, NULL, 0, KEY_WRITE, NULL, &k, NULL) != ERROR_SUCCESS) return;
  _snwprintf_s(cmd, MAX_PATH + 16, _TRUNCATE, L"\"%s\" \"%%1\"", exe);
  RegSetValueExW(k, NULL, 0, REG_SZ, (const BYTE *)cmd, (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
  RegCloseKey(k);
}
static void key_from_arg(const wchar_t *arg) {
  const wchar_t *p = wcsstr(arg, L"k="); size_t n = 0;
  if (!p) return;
  if (p > arg && p[-1] != L'#' && p[-1] != L'?' && p[-1] != L'&') return;
  p += 2;
  while (p[n] && p[n] != L'&' && p[n] != L'#' && p[n] != L'/' && n < 255) n++;
  wcsncpy_s(g_keyFromLink, 256, p, n);
}

/* --------------------------------------------------------- the window ---- */
static void layout(void) {
  RECT c; int m, x, y, w, rowH, readoutH;
  GetClientRect(g_hwnd, &c); m = S(12); rowH = S(26); readoutH = S(150);
  x = m; y = m; w = c.right - 2 * m;
  MoveWindow(g_key, x, y, w, rowH, TRUE); y += rowH + S(6);
  MoveWindow(g_pin, x, y, S(110), rowH, TRUE);
  MoveWindow(g_show, x + S(118), y, S(140), rowH, TRUE);
  MoveWindow(g_card, x + S(266), y, S(170), rowH, TRUE); y += rowH + S(6);
  MoveWindow(g_status, x, y, w, S(20), TRUE); y += S(20) + S(4);
  MoveWindow(g_readout, x, c.bottom - m - readoutH, w, readoutH, TRUE);
  MoveWindow(g_credit, x, c.bottom - m - readoutH - S(20), w, S(18), TRUE);
  g_photoRc.left = x; g_photoRc.top = y; g_photoRc.right = x + w; g_photoRc.bottom = c.bottom - m - readoutH - S(24);
  ensure_stage();
}
static LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
  switch (msg) {
  case WM_CREATE:
    g_hwnd = h; g_dpi = window_dpi(h);
    g_font = CreateFontW(-S(12), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
    g_mono = CreateFontW(-S(11), 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Consolas");
    g_key = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", g_keyFromLink, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 0, 0, h, (HMENU)ID_KEY, g_hinst, NULL);
    g_pin = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, (HMENU)ID_PIN, g_hinst, NULL);
    SendMessageW(g_pin, EM_SETLIMITTEXT, 6, 0);
    SendMessageW(g_key, EM_SETCUEBANNER, TRUE, (LPARAM)L"Link key (the part after #k= in the link)");
    SendMessageW(g_pin, EM_SETCUEBANNER, TRUE, (LPARAM)L"PIN");
    g_show = CreateWindowExW(0, L"BUTTON", L"Show the photo", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 0, 0, 0, 0, h, (HMENU)ID_SHOW, g_hinst, NULL);
    g_card = CreateWindowExW(0, L"BUTTON", L"Save the share card", WS_CHILD | WS_VISIBLE | WS_DISABLED, 0, 0, 0, 0, h, (HMENU)ID_CARD, g_hinst, NULL);
    g_status = CreateWindowExW(0, L"STATIC", L"Type the link key and the PIN, then Show the photo.", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS, 0, 0, 0, 0, h, (HMENU)ID_STATUS, g_hinst, NULL);
    g_credit = CreateWindowExW(0, L"STATIC", L"\x00a9 Candid Color Systems \x00b7 this view is marked to its viewer \x00b7 the refusal is Windows' own, asked for by this program; a camera pointed at the screen still photographs it, marked", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS, 0, 0, 0, 0, h, (HMENU)ID_CREDIT, g_hinst, NULL);
    g_readout = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, 0, 0, 0, 0, h, (HMENU)ID_READOUT, g_hinst, NULL);
    { HWND ctl[] = { g_key, g_pin, g_show, g_card, g_status, g_credit }; int i; for (i = 0; i < 6; i++) SendMessageW(ctl[i], WM_SETFONT, (WPARAM)g_font, TRUE); SendMessageW(g_readout, WM_SETFONT, (WPARAM)g_mono, TRUE); }
    AddClipboardFormatListener(h);
    return 0;
  case WM_SIZE: layout(); InvalidateRect(h, NULL, TRUE); return 0;
  case WM_GETMINMAXINFO: { MINMAXINFO *mm = (MINMAXINFO *)lp; mm->ptMinTrackSize.x = S(480); mm->ptMinTrackSize.y = S(560); return 0; }
  case WM_ERASEBKGND: return 1;
  case WM_PAINT: {
    PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT c; HRGN rgn;
    GetClientRect(h, &c);
    rgn = CreateRectRgnIndirect(&g_photoRc); ExtSelectClipRgn(dc, rgn, RGN_DIFF); FillRect(dc, &c, (HBRUSH)(COLOR_BTNFACE + 1)); SelectClipRgn(dc, NULL); DeleteObject(rgn);
    if (g_stage) { HDC m = CreateCompatibleDC(dc); HGDIOBJ o = SelectObject(m, g_stage); BitBlt(dc, g_photoRc.left, g_photoRc.top, g_stageW, g_stageH, m, 0, 0, SRCCOPY); SelectObject(m, o); DeleteDC(m); }
    EndPaint(h, &ps); return 0; }
  case WM_COMMAND:
    if (LOWORD(wp) == ID_SHOW && HIWORD(wp) == BN_CLICKED) on_show();
    else if (LOWORD(wp) == ID_CARD && HIWORD(wp) == BN_CLICKED) save_share_card();
    return 0;
  case WM_DECRYPTED: on_decrypted((decrypt_result *)lp); return 0;
  case WM_RUNPROBE: run_self_captures(); return 0;
  case WM_TIMER:
    if (wp == TIMER_PROBE) { KillTimer(h, TIMER_PROBE); run_self_captures(); }
    else if (wp == TIMER_PRTSC) { KillTimer(h, TIMER_PRTSC); read_print_screen(0); if (g_probe) { write_probe_json(); PostQuitMessage(0); } }
    return 0;
  case WM_CLIPBOARDUPDATE:
    if (!g_probe && g_stage && (g_photo || g_testPattern)) read_print_screen(1);
    return 0;
  case WM_CONTEXTMENU: return 0;                 /* a right-click offers nothing */
  case WM_DESTROY: RemoveClipboardFormatListener(h); PostQuitMessage(0); return 0;
  }
  return DefWindowProcW(h, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hinst, HINSTANCE prev, PWSTR cmdline, int show) {
  WNDCLASSW wc; MSG m; int argc = 0, i; LPWSTR *argv; DWORD aff = 0;
  (void)prev; (void)cmdline;
  g_hinst = hinst;
  enable_dpi_awareness();
  CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  for (i = 1; argv && i < argc; i++) {
    if (!wcscmp(argv[i], L"--probe")) g_probe = TRUE;
    else if (!wcscmp(argv[i], L"--no-affinity")) g_noAffinity = TRUE;
    else if (!wcsncmp(argv[i], L"--out=", 6)) utf8_of(argv[i] + 6, g_outPath, MAX_PATH);
    else key_from_arg(argv[i]);
  }
  g_build = os_build();
  { BOOL comp = FALSE; DwmIsCompositionEnabled(&comp); g_composition = comp; }
  g_remote = GetSystemMetrics(SM_REMOTESESSION) != 0;
  if (!g_probe) register_url_scheme();

  memset(&wc, 0, sizeof wc); wc.lpfnWndProc = wndproc; wc.hInstance = hinst; wc.lpszClassName = L"CCSProofViewer"; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = NULL;
  RegisterClassW(&wc);
  g_hwnd = CreateWindowExW(0, wc.lpszClassName, g_probe ? L"CCS Proof Viewer, probe" : L"CCS Proof Viewer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, S(640), S(900), NULL, NULL, hinst, NULL);
  if (!g_hwnd) return 1;
  /* The refusal, asked for before the first frame. */
  if (!g_noAffinity) g_affinitySetOk = SetWindowDisplayAffinity(g_hwnd, WDA_EXCLUDEFROMCAPTURE); else g_affinitySetOk = FALSE;
  if (GetWindowDisplayAffinity(g_hwnd, &aff)) g_affinityRead = aff; else g_affinityRead = 0xFFFFFFFF;
  if (g_probe) { g_testPattern = TRUE; }
  layout(); refresh_readout();
  ShowWindow(g_hwnd, g_probe ? SW_SHOW : show); UpdateWindow(g_hwnd);
  if (g_probe) { SetForegroundWindow(g_hwnd); SetTimer(g_hwnd, TIMER_PROBE, 700, NULL); }
  while (GetMessageW(&m, NULL, 0, 0) > 0) { if (!IsDialogMessageW(g_hwnd, &m)) { TranslateMessage(&m); DispatchMessageW(&m); } }
  CoUninitialize();
  return 0;
}
