"""File metadata extraction and content-based file-type identification.

This runs as part of the static-analysis workflow: it never executes the
sample. It answers "what is this file, and what does its shape tell us before
we look deeper" -- size, real file type (from magic bytes, not the extension),
byte entropy (a strong packed/encrypted indicator), and whether the declared
extension matches the actual content (a common malware disguise).
"""

import math
import os
from dataclasses import dataclass

# Number of leading bytes recorded as the hex "magic" preview in the report.
_MAGIC_PREVIEW_BYTES = 16

# Shannon entropy (bits/byte) above which binary content is likely packed,
# compressed, or encrypted. 8.0 is the theoretical maximum.
_PACKED_ENTROPY_THRESHOLD = 7.2

# Bytes inspected for the text-vs-binary decision.
_TEXT_SNIFF_BYTES = 8192


@dataclass(frozen=True)
class _Signature:
    """A magic-byte signature. ``magic`` is matched at ``offset`` in the file."""

    file_type: str
    mime_type: str
    magic: bytes
    offset: int = 0


# Ordered roughly most-specific first. Deliberately small and readable -- extend
# it as new sample types show up during testing rather than pulling in libmagic.
_SIGNATURES: tuple[_Signature, ...] = (
    _Signature('ELF executable (Unix/Linux)', 'application/x-executable', b'\x7fELF'),
    _Signature('Mach-O executable (macOS, 32-bit)', 'application/x-mach-binary', b'\xfe\xed\xfa\xce'),
    _Signature('Mach-O executable (macOS, 64-bit)', 'application/x-mach-binary', b'\xfe\xed\xfa\xcf'),
    _Signature('Mach-O executable (macOS, little-endian)', 'application/x-mach-binary', b'\xcf\xfa\xed\xfe'),
    _Signature('Java class file', 'application/java-vm', b'\xca\xfe\xba\xbe'),
    _Signature('PDF document', 'application/pdf', b'%PDF-'),
    _Signature('ZIP archive / OOXML / JAR', 'application/zip', b'PK\x03\x04'),
    _Signature('RAR archive', 'application/vnd.rar', b'Rar!\x1a\x07'),
    _Signature('7-Zip archive', 'application/x-7z-compressed', b'7z\xbc\xaf\x27\x1c'),
    _Signature('gzip archive', 'application/gzip', b'\x1f\x8b'),
    _Signature('Legacy MS Office / OLE2 compound file', 'application/x-ole-storage', b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'),
    _Signature('Windows shortcut (LNK)', 'application/x-ms-shortcut', b'\x4c\x00\x00\x00\x01\x14\x02\x00'),
    _Signature('PNG image', 'image/png', b'\x89PNG\r\n\x1a\n'),
    _Signature('GIF image', 'image/gif', b'GIF8'),
    _Signature('JPEG image', 'image/jpeg', b'\xff\xd8\xff'),
    _Signature('Shell script', 'text/x-shellscript', b'#!'),
)

# Content type -> extensions that legitimately carry that content. Used to flag
# files whose extension disagrees with their real type.
_TYPE_EXTENSIONS: dict[str, set[str]] = {
    'application/vnd.microsoft.portable-executable': {'.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl', '.efi'},
    'application/x-dosexec': {'.exe', '.dll', '.com', '.scr'},
    'application/x-executable': {'', '.elf', '.so', '.bin', '.o', '.out'},
    'application/x-mach-binary': {'', '.dylib', '.bundle', '.o'},
    'application/java-vm': {'.class'},
    'application/pdf': {'.pdf'},
    'application/zip': {'.zip', '.jar', '.apk', '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp', '.epub'},
    'application/vnd.rar': {'.rar'},
    'application/x-7z-compressed': {'.7z'},
    'application/gzip': {'.gz', '.tgz'},
    'application/x-ole-storage': {'.doc', '.xls', '.ppt', '.msi', '.msg'},
    'application/x-ms-shortcut': {'.lnk'},
    'image/png': {'.png'},
    'image/gif': {'.gif'},
    'image/jpeg': {'.jpg', '.jpeg', '.jpe'},
    'text/x-shellscript': {'.sh', '.bash', ''},
    'text/plain': {'.txt', '.log', '.csv', '.ini', '.cfg', '.json', '.xml', '.md', ''},
}


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0.0-8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def _printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII text or common whitespace."""
    if not data:
        return 0.0
    printable = sum(1 for byte in data if 32 <= byte <= 126 or byte in (9, 10, 13))
    return printable / len(data)


def _identify_pe(data: bytes) -> tuple[str, str] | None:
    """Distinguish a real PE (Windows exe/dll) from a bare DOS ``MZ`` stub.

    A PE file starts with ``MZ``; the 4-byte little-endian value at offset 0x3C
    points to a ``PE\\x00\\x00`` signature.
    """
    if not data.startswith(b'MZ'):
        return None
    if len(data) >= 0x40:
        pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
        if 0 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b'PE\x00\x00':
            return 'PE executable (Windows)', 'application/vnd.microsoft.portable-executable'
    return 'DOS/MZ executable', 'application/x-dosexec'


def _identify_type(data: bytes) -> tuple[str, str]:
    """Return ``(file_type, mime_type)`` from content, falling back to text/binary."""
    pe = _identify_pe(data)
    if pe is not None:
        return pe

    for signature in _SIGNATURES:
        window = data[signature.offset:signature.offset + len(signature.magic)]
        if window == signature.magic:
            return signature.file_type, signature.mime_type

    if not data:
        return 'empty file', 'inode/x-empty'

    sample = data[:_TEXT_SNIFF_BYTES]
    if b'\x00' not in sample and _printable_ratio(sample) >= 0.95:
        return 'plain text', 'text/plain'
    return 'unknown binary', 'application/octet-stream'


def extract_metadata(data: bytes, filename: str | None = None) -> dict[str, object]:
    """Extract static metadata for an uploaded sample.

    Args:
        data: Raw file bytes. Never executed.
        filename: Original upload name, if known -- used only to read the
            declared extension and check it against the detected content type.

    Returns a JSON-serialisable dict; see ``FileMetadata`` in ``schemas.py`` for
    the field contract.
    """
    file_type, mime_type = _identify_type(data)
    entropy = shannon_entropy(data)
    printable = _printable_ratio(data)

    extension: str | None = None
    extension_matches_content: bool | None = None
    if filename:
        extension = os.path.splitext(filename)[1].lower()
        allowed = _TYPE_EXTENSIONS.get(mime_type)
        if allowed is not None:
            extension_matches_content = extension in allowed

    is_binary = b'\x00' in data[:_TEXT_SNIFF_BYTES] or printable < 0.95
    likely_packed = is_binary and entropy >= _PACKED_ENTROPY_THRESHOLD

    return {
        'size_bytes': len(data),
        'file_type': file_type,
        'mime_type': mime_type,
        'magic_hex': data[:_MAGIC_PREVIEW_BYTES].hex(),
        'extension': extension,
        'extension_matches_content': extension_matches_content,
        'shannon_entropy': round(entropy, 4),
        'likely_packed': likely_packed,
        'printable_ratio': round(printable, 4),
        'likely_text': not is_binary,
    }
