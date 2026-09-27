"""Cryptographic hashing for static malware analysis.

File digests are the primary identifier for a sample. They let the platform
deduplicate uploads, look a sample up in external threat-intel sources
(VirusTotal, MalwareBazaar), and match it against hash-based blocklists and
signatures without ever executing the file.
"""

import hashlib
from typing import BinaryIO

# MD5 and SHA-256 are required by the static-analysis spec. SHA-1 is included
# because virtually every threat-intel service keys on all three.
HASH_ALGORITHMS: tuple[str, ...] = ('md5', 'sha1', 'sha256')

# Read large uploads in fixed-size chunks so we never hold the whole file in RAM.
_STREAM_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def _new_hashers() -> dict[str, 'hashlib._Hash']:
    return {name: hashlib.new(name) for name in HASH_ALGORITHMS}


def calculate_hashes(data: bytes) -> dict[str, str]:
    """Return hex digests of ``data`` for every algorithm in ``HASH_ALGORITHMS``.

    Keys: ``md5``, ``sha1``, ``sha256``.
    """
    hashers = _new_hashers()
    for hasher in hashers.values():
        hasher.update(data)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def calculate_hashes_stream(stream: BinaryIO) -> dict[str, str]:
    """Hash a binary stream in chunks.

    Use this instead of :func:`calculate_hashes` when the sample is large enough
    that loading it fully into memory is wasteful. The stream is read from its
    current position to EOF and is not rewound.
    """
    hashers = _new_hashers()
    for chunk in iter(lambda: stream.read(_STREAM_CHUNK_SIZE), b''):
        for hasher in hashers.values():
            hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}
