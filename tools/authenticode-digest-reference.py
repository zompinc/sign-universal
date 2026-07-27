#!/usr/bin/env python3
"""Reference implementation of the Authenticode PE digest.

A deliberately naive, dependency-free transcription of the hashing algorithm in
"Windows Authenticode Portable Executable Signature Format", kept separate from the
C# engine so the two can disagree. It backs the known-answer vectors in
PeDigestTests and doubles as an offline oracle on machines without signtool.

Usage:
  authenticode-digest-reference.py FILE...            print each file's digest
  authenticode-digest-reference.py --check DIR...     self-check against signed PEs

--check walks the directories for Authenticode-signed PE images, recomputes each
digest, and confirms it appears inside that file's own embedded signature. Any
directory of Microsoft-signed binaries works; a NuGet package cache is a convenient
source of several thousand, covering both PE32 and PE32+.
"""

import hashlib
import os
import struct
import sys

CERTIFICATE_DIRECTORY_INDEX = 4


def parse(image):
    """Return the header offsets the digest depends on."""
    if image[:2] != b"MZ":
        raise ValueError("not a PE image: missing 'MZ' signature")

    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image: missing 'PE\\0\\0' signature")

    section_count = struct.unpack_from("<H", image, pe + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe + 20)[0]
    optional = pe + 24

    magic = struct.unpack_from("<H", image, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported optional header magic 0x%X" % magic)
    pe32_plus = magic == 0x20B

    # SizeOfHeaders and CheckSum sit at the same optional-header offsets in both
    # formats; the data directories do not.
    directories = optional + (112 if pe32_plus else 96)
    certificate_directory = directories + CERTIFICATE_DIRECTORY_INDEX * 8
    rva_count = struct.unpack_from("<I", image, optional + (108 if pe32_plus else 92))[0]
    if rva_count <= CERTIFICATE_DIRECTORY_INDEX:
        raise ValueError("image has no attribute-certificate data directory")

    table_offset, table_size = struct.unpack_from("<II", image, certificate_directory)

    sections = []
    section_table = optional + optional_size
    for i in range(section_count):
        entry = section_table + i * 40
        raw_size = struct.unpack_from("<I", image, entry + 16)[0]
        raw_offset = struct.unpack_from("<I", image, entry + 20)[0]
        if raw_size:
            sections.append((raw_offset, raw_size))

    return {
        "pe32_plus": pe32_plus,
        "checksum": optional + 64,
        "certificate_directory": certificate_directory,
        "table_offset": table_offset,
        "table_size": table_size,
        "size_of_headers": struct.unpack_from("<I", image, optional + 60)[0],
        "sections": sections,
    }


def digest(image, headers, algorithm="sha256"):
    """Compute the Authenticode digest of an in-memory PE image."""
    accumulator = hashlib.new(algorithm)

    # Headers, minus the CheckSum field and the certificate directory entry: the two
    # ranges signing itself rewrites.
    accumulator.update(image[0:headers["checksum"]])
    accumulator.update(image[headers["checksum"] + 4:headers["certificate_directory"]])
    accumulator.update(image[headers["certificate_directory"] + 8:headers["size_of_headers"]])

    hashed = headers["size_of_headers"]
    for offset, size in sorted(headers["sections"]):
        accumulator.update(image[offset:offset + size])
        hashed += size

    # Whatever trails the last section, except the certificate table itself.
    trailing = len(image) - headers["table_size"] - hashed
    if trailing > 0:
        accumulator.update(image[hashed:hashed + trailing])

    return accumulator.hexdigest()


def check(paths):
    """Recompute digests of signed PEs and look for each inside its own signature."""
    matched = mismatched = 0
    for root in paths:
        for directory, _, names in os.walk(root):
            for name in names:
                path = os.path.join(directory, name)
                try:
                    with open(path, "rb") as handle:
                        image = handle.read()
                    headers = parse(image)
                except (ValueError, OSError, struct.error):
                    continue
                if not headers["table_size"]:
                    continue

                table = image[headers["table_offset"]:headers["table_offset"] + headers["table_size"]]
                for algorithm in ("sha256", "sha384", "sha512", "sha1"):
                    if bytes.fromhex(digest(image, headers, algorithm)) in table:
                        matched += 1
                        break
                else:
                    mismatched += 1
                    print("MISMATCH %s" % path)

    print("%d signed images matched, %d mismatched" % (matched, mismatched))
    return 1 if mismatched else 0


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2

    if argv[1] == "--check":
        return check(argv[2:] or ["."])

    for path in argv[1:]:
        with open(path, "rb") as handle:
            image = handle.read()
        print("%s  %s" % (digest(image, parse(image)), path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
