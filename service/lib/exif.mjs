// Reads the EXIF orientation (1..8) of a JPEG from its APP1 segment, so a phone photo taken sideways
// is rendered the way the phone shows it. Returns 1 (upright) when there is no orientation tag.
// Pure byte reading; no library.
export function jpegOrientation(buf) {
  if (!(buf.length > 4 && buf[0] === 0xff && buf[1] === 0xd8)) return 1;
  let off = 2;
  while (off + 4 <= buf.length) {
    if (buf[off] !== 0xff) return 1;
    const marker = buf[off + 1];
    if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) { off += 2; continue; }
    if (marker === 0xda || marker === 0xd9) return 1; // image data begins, or end: no APP1 seen
    const len = buf.readUInt16BE(off + 2);
    if (len < 2) return 1;
    if (marker === 0xe1 && buf.subarray(off + 4, off + 10).toString("latin1") === "Exif\0\0") {
      const tiff = off + 10;
      if (tiff + 8 > buf.length) return 1;
      const order = buf.subarray(tiff, tiff + 2).toString("latin1");
      const le = order === "II";
      if (!le && order !== "MM") return 1;
      const u16 = (p) => (le ? buf.readUInt16LE(p) : buf.readUInt16BE(p));
      const u32 = (p) => (le ? buf.readUInt32LE(p) : buf.readUInt32BE(p));
      if (u16(tiff + 2) !== 0x2a) return 1;
      const ifd = tiff + u32(tiff + 4);
      if (ifd + 2 > buf.length) return 1;
      const n = u16(ifd);
      for (let i = 0; i < n; i++) {
        const e = ifd + 2 + i * 12;
        if (e + 12 > buf.length) return 1;
        if (u16(e) === 0x0112 && u16(e + 2) === 3) {
          const v = u16(e + 8);
          return v >= 1 && v <= 8 ? v : 1;
        }
      }
      return 1;
    }
    off += 2 + len;
  }
  return 1;
}

// The ffmpeg filter that undoes each EXIF orientation (the input is read with -noautorotate, so this
// is applied exactly once). "" means upright.
export const ORIENTATION_FILTER = {
  1: "", 2: "hflip", 3: "hflip,vflip", 4: "vflip", 5: "transpose=0", 6: "transpose=1", 7: "transpose=3", 8: "transpose=2",
};

// Builds a JPEG APP1 (EXIF) segment carrying only an orientation tag, for tests.
export function exifSegmentWithOrientation(orientation) {
  const tiff = Buffer.alloc(8 + 2 + 12 + 4);
  tiff.write("MM", 0, "latin1"); tiff.writeUInt16BE(0x2a, 2); tiff.writeUInt32BE(8, 4);
  tiff.writeUInt16BE(1, 8);
  tiff.writeUInt16BE(0x0112, 10); tiff.writeUInt16BE(3, 12); tiff.writeUInt32BE(1, 14); tiff.writeUInt16BE(orientation, 18);
  tiff.writeUInt32BE(0, 22);
  const payload = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), tiff]);
  const seg = Buffer.alloc(4);
  seg[0] = 0xff; seg[1] = 0xe1; seg.writeUInt16BE(payload.length + 2, 2);
  return Buffer.concat([seg, payload]);
}

// Inserts an EXIF segment right after SOI of a JPEG, for tests.
export function withOrientation(jpeg, orientation) {
  return Buffer.concat([jpeg.subarray(0, 2), exifSegmentWithOrientation(orientation), jpeg.subarray(2)]);
}
