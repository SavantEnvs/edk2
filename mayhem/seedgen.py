#!/usr/bin/env python3
"""Regenerate the structured seeds under mayhem/<target>/testsuite (run from the repo root).

The outputs are committed; this script records where they come from:
  * FMP authentication images (TestFmpAuthenticationLib*): the payload of the Quark capsules HBFA
    ships in Seed/Capsule (a real PKCS7-signed and a real RSA2048-SHA256-signed image), plus
    minimal hand-built headers that pass AuthenticateFmpImage()'s format gate.
  * TPM2_PCR_Event responses (TestTpm2CommandLib): one per hash algorithm, all of them, and
    the count/algorithm error branches.
  * USB configuration descriptor blobs (TestPeiUsb): the two device examples from HBFA's
    UsbIoPpiStubLib plus multi-interface variants.
  * UDF disks (TestPartition, TestUdf): HBFA's Seed/UDF/Raw images re-encoded in the sparse
    record format of mayhem/SparseImage.h (the originals are 512 KiB to 1 MiB, Mayhem's input cap
    is 8 KiB). Needs a checkout of intel/hbfa-fl: `seedgen.py --hbfa <dir>`.
"""
import os
import struct
import sys

CAPSULES = "mayhem/TestCapsulePei/testsuite"
PKCS7_GUID = bytes.fromhex("9dd2af4adf68ee498aa9347d375665a7")      # gEfiCertPkcs7Guid
RSA_GUID = bytes.fromhex("147471a716c677499420844712a735bf")        # gEfiCertTypeRsa2048Sha256Guid
SHA256_GUID = bytes.fromhex("de59aa51f2fda34ebc63875fb7842ee9")     # gEfiHashAlgorithmSha256Guid


def put(target, name, data):
    d = os.path.join("mayhem", target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


def fmp_payload(cap):
    """Return the first payload image of an FMP capsule (the EFI_FIRMWARE_IMAGE_AUTHENTICATION blob)."""
    d = open(os.path.join(CAPSULES, cap), "rb").read()
    hs = struct.unpack_from("<I", d, 16)[0]
    _, emb, pay = struct.unpack_from("<IHH", d, hs)
    off = struct.unpack_from("<%dQ" % (emb + pay), d, hs + 8)[emb]
    p = hs + off
    ver = struct.unpack_from("<I", d, p)[0]
    size = struct.unpack_from("<I", d, p + 24)[0]
    hdr = {1: 32, 2: 40, 3: 48}[ver]
    return d[p + hdr:p + hdr + size]


def auth_image(count, cert_type, cert_data, payload, revision=0x0200):
    dw_length = 24 + len(cert_data)
    return struct.pack("<QIHH", count, dw_length, revision, 0x0EF1) + cert_type + cert_data + payload


def fmp_seeds():
    pkcs7 = fmp_payload("QUARKFIRMWAREUPDATECAPSULEFMPPKCS7.Cap")
    rsa = fmp_payload("QUARKREC.Cap")
    payload = bytes(range(64))
    put("TestFmpAuthenticationLibPkcs7", "quark_pkcs7_signed.bin", pkcs7)
    put("TestFmpAuthenticationLibPkcs7", "minimal_pkcs7.bin", auth_image(1, PKCS7_GUID, bytes(8), payload))
    put("TestFmpAuthenticationLibPkcs7", "pkcs7_one_byte_payload.bin", auth_image(7, PKCS7_GUID, bytes(32), b"\x5a"))
    put("TestFmpAuthenticationLibPkcs7", "unsupported_cert_type.bin", auth_image(1, RSA_GUID, bytes(8), payload))
    put("TestFmpAuthenticationLibPkcs7", "bad_revision.bin", auth_image(1, PKCS7_GUID, bytes(8), payload, 0x0100))

    blk = SHA256_GUID + bytes(range(256)) + bytes(reversed(range(256)))
    put("TestFmpAuthenticationLibRsa2048Sha256", "quark_rsa2048_sha256_signed.bin", rsa)
    put("TestFmpAuthenticationLibRsa2048Sha256", "minimal_rsa2048_sha256.bin", auth_image(1, RSA_GUID, blk, payload))
    put("TestFmpAuthenticationLibRsa2048Sha256", "wrong_hash_type.bin", auth_image(1, RSA_GUID, bytes(16) + blk[16:], payload))
    put("TestFmpAuthenticationLibRsa2048Sha256", "unsupported_cert_type.bin", auth_image(1, PKCS7_GUID, bytes(8), payload))
    put("TestFmpAuthenticationLibRsa2048Sha256", "short_cert_block.bin", auth_image(1, RSA_GUID, blk[:100], payload))


def tpm_response(count, algs):
    body = struct.pack(">I", count)
    for i, (alg, size) in enumerate(algs):
        body += struct.pack(">H", alg) + bytes(((i * 37 + j) & 0xFF) for j in range(size))
    total = 10 + 4 + len(body) + 10
    return struct.pack(">HII", 0x8002, total, 0) + struct.pack(">I", total - 10) + body + bytes(10)


def tpm_seeds():
    sha1, sha256, sha384, sha512, sm3 = (0x4, 20), (0xB, 32), (0xC, 48), (0xD, 64), (0x12, 32)
    cases = {
        "pcr_event_sha1": [sha1],
        "pcr_event_sha256": [sha256],
        "pcr_event_sha384": [sha384],
        "pcr_event_sha512": [sha512],
        "pcr_event_sm3_256": [sm3],
        "pcr_event_all_five": [sha1, sha256, sha384, sha512, sm3],
        "pcr_event_sha1_sha256": [sha1, sha256],
    }
    for name, algs in cases.items():
        put("TestTpm2CommandLib", name + ".bin", tpm_response(len(algs), algs))
    put("TestTpm2CommandLib", "pcr_event_zero_digests.bin", tpm_response(0, []))
    put("TestTpm2CommandLib", "pcr_event_count_over_hash_count.bin", tpm_response(6, [sha256] * 6))
    put("TestTpm2CommandLib", "pcr_event_unknown_alg.bin", tpm_response(1, [(0x1, 32)]))


def usb_config(interfaces):
    """interfaces: list of (class, subclass, protocol, [extra class descriptors], [endpoints])."""
    body = b""
    for n, (cls, sub, proto, extra, eps) in enumerate(interfaces):
        body += bytes([9, 4, n, 0, len(eps), cls, sub, proto, 0])
        for e in extra:
            body += e
        for addr, attrs, mps, interval in eps:
            body += struct.pack("<BBBBHB", 7, 5, addr, attrs, mps, interval)
    return struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), len(interfaces), 1, 0, 0xA0, 0x32) + body


def usb_seeds():
    hid = struct.pack("<BBHBBBH", 9, 0x21, 0x0110, 0, 1, 0x22, 0x41)
    put("TestPeiUsb", "hid_keyboard.bin", usb_config([(3, 1, 1, [hid], [(0x81, 3, 8, 10)])]))
    put("TestPeiUsb", "mass_storage_bot.bin", usb_config([(8, 6, 0x50, [], [(0x81, 2, 0x200, 0), (0x01, 2, 0x200, 1)])]))
    put("TestPeiUsb", "two_interfaces.bin", usb_config([
        (3, 1, 1, [hid], [(0x81, 3, 8, 10)]),
        (8, 6, 0x50, [], [(0x82, 2, 0x200, 0), (0x02, 2, 0x200, 1)]),
    ]))
    put("TestPeiUsb", "hub_interface.bin", usb_config([(9, 0, 0, [], [(0x81, 3, 1, 12)])]))
    put("TestPeiUsb", "no_endpoints.bin", usb_config([(0xFF, 0, 0, [], [])]))


def sparse_encode(image, gap=8, max_size=8192):
    """Records (offset u32, length u16, data) covering every non-zero byte of image, zero runs
    of at most `gap` bytes merged into the neighbouring record. None if it exceeds max_size."""
    runs = []
    for i, b in enumerate(image):
        if b:
            if runs and i - runs[-1][1] <= gap:
                runs[-1][1] = i + 1
            else:
                runs.append([i, i + 1])
    out = b""
    for start, end in runs:
        while start < end:
            n = min(end - start, 0xFFFF)
            out += struct.pack("<IH", start, n) + image[start:start + n]
            start += n
    return out if len(out) <= max_size else None


def udf_seeds(hbfa):
    raw = os.path.join(hbfa, "HBFA/UefiHostFuzzTestCasePkg/Seed/UDF/Raw")
    for target, sub in (("TestPartition", "Partition"), ("TestUdf", "FileSystem")):
        d = os.path.join("mayhem", target, "testsuite")
        for name in sorted(os.listdir(d)):
            enc = sparse_encode(open(os.path.join(raw, sub, name), "rb").read())
            if enc is None:
                os.remove(os.path.join(d, name))
                print("dropped (over 8 KiB sparse):", target, name)
            else:
                put(target, name, enc)


if __name__ == "__main__":
    if not os.path.isdir(CAPSULES):
        sys.exit("run from the repo root")
    fmp_seeds()
    tpm_seeds()
    usb_seeds()
    if "--hbfa" in sys.argv:
        udf_seeds(sys.argv[sys.argv.index("--hbfa") + 1])
