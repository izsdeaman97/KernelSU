#!/usr/bin/env python3
"""Print KSU_EXPECTED_SIZE / KSU_EXPECTED_HASH for a signed manager APK.

Mirrors kernel/manager/apk_sign.c: takes the first certificate of the first
signer in the APK Signature Scheme v2 block and prints its DER length and
SHA-256.

Usage: python3 scripts/apk_sign_info.py app-release.apk
"""
import hashlib
import struct
import sys


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def main(path):
    data = open(path, "rb").read()
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        sys.exit("EOCD not found")
    cd_offset = u32(data, eocd + 16)
    if data[cd_offset - 16:cd_offset] != b"APK Sig Block 42":
        sys.exit("APK Signing Block not found (APK must be signed with v2)")
    block_size = struct.unpack_from("<Q", data, cd_offset - 24)[0]
    pos = cd_offset - block_size - 8 + 8
    end = cd_offset - 24
    while pos < end:
        pair_size = struct.unpack_from("<Q", data, pos)[0]
        pid = u32(data, pos + 8)
        if pid == 0x7109871A:
            p = pos + 12
            p += 4  # signers length
            p += 4  # first signer length
            p += 4  # signed data length
            p += 4 + u32(data, p)  # skip digests
            p += 4  # certificates length
            cert_len = u32(data, p)
            cert = data[p + 4:p + 4 + cert_len]
            print("KSU_CUSTOM_EXPECTED_SIZE=0x%04x" % cert_len)
            print("KSU_CUSTOM_EXPECTED_HASH=%s" % hashlib.sha256(cert).hexdigest())
            return
        pos += 8 + pair_size
    sys.exit("v2 signature block not found")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
