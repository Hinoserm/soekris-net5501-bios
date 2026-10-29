#!/usr/bin/env python3
"""Patch Soekris comBIOS 1.33c for the net5501 (b5501_133c.bin) into 1.33x.

Usage: patch_b5501.py IN OUT

IN must be the original b5501_133c.bin (checked by SHA-256).
"""
import hashlib, struct, sys

ORIG_SHA = "f14ef586478d2f198c9888a1fda46a091f0a1eb0eb2fc5435c5148598bef1bb0"
MAIN = 0xA800                      # SK_R type-2 module (main BIOS); BIOS offsets below are relative to it

# (file offset, old bytes, new bytes, what it does)
PATCH = [
    # Large CF cards: the CHS translation divided by heads*63 after a head count that only works up to
    # ~8.4 GB of CHS geometry, so DIV at 0x29AF overflowed and the divide-error handler (a bare iret)
    # re-ran it forever. Cap the CHS product at 0xFC0000 sectors, the 16383/16/63 limit.
    (MAIN + 0x2973, bytes.fromhex("81faf00f"), bytes.fromhex("81fafc00"), "cmp dx,0xff0 -> cmp dx,0xfc"),
    (MAIN + 0x2979, bytes.fromhex("baf00f"),   bytes.fromhex("bafc00"),   "mov dx,0xff0 -> mov dx,0xfc"),
    # Version and date.
    (MAIN + 0x002D, b"1.33c 20080626", b"1.33x 20261028", "banner"),
    (0x187F5,       b"20080626",       b"20261028",       "date beside the reset vector"),
    # PCI option ROMs: the ROM BAR was written from the dword at [0x15], a byte past the ROM base at
    # [0x14], so the enable bit was never set and the ROM never decoded. A helper in unused padding
    # after 0x2512 writes [0x14] | 1 and tail-jumps to the PCI config-write routine at 0x54F8.
    (MAIN + 0x2513, bytes(11), bytes.fromhex("668b0e1400" "80c901" "e9da2f"), "ROM BAR helper"),
    (MAIN + 0x5776, bytes.fromhex("668b0e1500e87afd"), bytes.fromhex("e89acd9090909090"), "VGA ROM BAR"),
    (MAIN + 0x5BD3, bytes.fromhex("668b0e1500e81df9"), bytes.fromhex("e83dc99090909090"), "other option ROM BARs"),
    # The VGA ROM was entered with AX = 0x0100 (bus 1, device 0) left in BX by 0x3CA5, instead of the
    # card's bus/devfn, which 0x3CA5 has just restored into CX. The invalid-ROM branch (always a failure:
    # 0x3CF6 is stc/ret) goes straight to the failure exit at 0x55A6, and the freed bytes hold mov bx,cx.
    (MAIN + 0x558C, bytes.fromhex("7408"), bytes.fromhex("7418"), "invalid ROM -> failure exit"),
    (MAIN + 0x5594, bytes.fromhex("eb05e85de7720b"), bytes.fromhex("8bd99090909090"), "VGA ROM gets its bus/devfn in AX"),
]

def sum16(b):
    return sum(struct.unpack_from("<%dH" % (len(b) // 2), b)) & 0xFFFF

def modules(d):
    """Walk the image the way flashupdate does; return the SK_R modules."""
    p, out = 0, []
    while d[p:p+2] == b"\x55\xaa":             # option ROMs
        p += d[p+2] * 512
    while p < len(d):
        if d[p:p+4] == b"\xff" * 4: p += 0x200; continue
        if d[p:p+4] == b"-BCP": p += 0x1000; continue
        if d[p:p+4] != b"SK_R": sys.exit(f"unexpected data at {p:#x}")
        ln, typ, magic, rev = struct.unpack_from("<HBxBB", d, p + 4)
        if magic != 0x55: sys.exit(f"module at {p:#x}: byte 8 is not 0x55")
        out.append((p, ln * 256)); p += ln * 256
    if p != len(d): sys.exit("modules do not end at the end of the file")
    return out

def main(argv):
    if len(argv) != 2: sys.exit(__doc__)
    src, dst = argv
    d = bytearray(open(src, "rb").read())
    if hashlib.sha256(d).hexdigest() != ORIG_SHA: sys.exit("not the expected b5501_133c.bin")
    for off, old, new, _ in PATCH:
        if d[off:off+len(old)] != old: sys.exit(f"unexpected bytes at {off:#x}")
        d[off:off+len(new)] = new
    # Each SK_R module carries a word at +0x0E that makes its 16-bit words sum to 0.
    for p, ln in modules(d):
        if any(p <= off < p + ln for off, _, _, _ in PATCH):
            d[p+0xE:p+0x10] = b"\0\0"
            d[p+0xE:p+0x10] = struct.pack("<H", (-sum16(d[p:p+ln])) & 0xFFFF)
    for p, ln in modules(d) + [(MAIN + 0xB000, 0x1000)]:    # a type-5 module sits inside the main one
        assert sum16(d[p:p+ln]) == 0, hex(p)
    assert sum(d[:d[2] * 512]) & 0xFF == 0                    # the PXE option ROM's own byte sum
    open(dst, "wb").write(d)
    print("wrote", dst, hashlib.sha256(d).hexdigest())

main(sys.argv[1:])
