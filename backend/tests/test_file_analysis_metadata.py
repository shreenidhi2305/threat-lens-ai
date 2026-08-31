import os

from app.modules.file_analysis.analyzers.metadata import (
    extract_metadata,
    shannon_entropy,
)

# Minimal but valid-enough headers for content-based detection.
PE_BYTES = b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 64
DOS_ONLY = b"MZ" + b"\x00" * 128  # MZ stub with no PE header
PDF_BYTES = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< >>\nendobj\n"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
ZIP_BYTES = b"PK\x03\x04" + b"\x00" * 32
ELF_BYTES = b"\x7fELF" + b"\x00" * 60


def test_size_is_reported():
    assert extract_metadata(b"abcde")["size_bytes"] == 5


def test_detects_pe_executable():
    meta = extract_metadata(PE_BYTES)
    assert meta["file_type"] == "PE executable (Windows)"
    assert meta["mime_type"] == "application/vnd.microsoft.portable-executable"


def test_distinguishes_bare_mz_stub_from_pe():
    assert extract_metadata(DOS_ONLY)["file_type"] == "DOS/MZ executable"


def test_detects_common_formats():
    assert extract_metadata(PDF_BYTES)["file_type"] == "PDF document"
    assert extract_metadata(PNG_BYTES)["file_type"] == "PNG image"
    assert extract_metadata(ZIP_BYTES)["mime_type"] == "application/zip"
    assert extract_metadata(ELF_BYTES)["file_type"].startswith("ELF executable")


def test_plain_text_vs_binary_classification():
    text_meta = extract_metadata(b"the quick brown fox jumps over the lazy dog\n" * 5)
    assert text_meta["likely_text"] is True
    assert text_meta["mime_type"] == "text/plain"

    bin_meta = extract_metadata(bytes(range(256)) * 4)
    assert bin_meta["likely_text"] is False


def test_empty_file():
    meta = extract_metadata(b"")
    assert meta["file_type"] == "empty file"
    assert meta["shannon_entropy"] == 0.0


def test_extension_mismatch_is_flagged():
    disguised = extract_metadata(PE_BYTES, filename="invoice.pdf")
    assert disguised["extension"] == ".pdf"
    assert disguised["extension_matches_content"] is False

    honest = extract_metadata(PE_BYTES, filename="payload.exe")
    assert honest["extension_matches_content"] is True


def test_extension_check_skipped_without_filename():
    assert extract_metadata(PE_BYTES)["extension_matches_content"] is None


def test_high_entropy_binary_is_flagged_as_packed():
    # os.urandom is incompressible -> entropy approaches 8.0 bits/byte.
    meta = extract_metadata(os.urandom(4096))
    assert meta["shannon_entropy"] > 7.5
    assert meta["likely_packed"] is True


def test_low_entropy_is_not_flagged_as_packed():
    assert extract_metadata(b"\x00" * 4096)["likely_packed"] is False


def test_shannon_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x41" * 100) == 0.0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9
