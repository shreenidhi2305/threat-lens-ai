import hashlib
import io

from app.modules.file_analysis.analyzers.hashing import (
    HASH_ALGORITHMS,
    calculate_hashes,
    calculate_hashes_stream,
)

# Known-answer vectors (NIST / RFC test values).
EMPTY = {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
ABC = {
    "md5": "900150983cd24fb0d6963f7d28e17f72",
    "sha1": "a9993e364706816aba3e25717850c26c9cd0d89d",
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
}


def test_calculate_hashes_empty_input():
    assert calculate_hashes(b"") == EMPTY


def test_calculate_hashes_known_vector():
    assert calculate_hashes(b"abc") == ABC


def test_calculate_hashes_covers_every_declared_algorithm():
    result = calculate_hashes(b"threatlens")
    assert set(result) == set(HASH_ALGORITHMS)


def test_stream_matches_in_memory_for_multi_chunk_input():
    payload = b"malware-sample-bytes" * 200_000  # ~3.8 MiB, spans several chunks
    assert calculate_hashes_stream(io.BytesIO(payload)) == calculate_hashes(payload)


def test_stream_matches_reference_implementation():
    payload = bytes(range(256)) * 1000
    expected = {name: hashlib.new(name, payload).hexdigest() for name in HASH_ALGORITHMS}
    assert calculate_hashes_stream(io.BytesIO(payload)) == expected
