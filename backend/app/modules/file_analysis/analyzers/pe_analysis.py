"""PE header analysis for Windows executables.

Part of the Static Analysis Workflow ("PE header analysis" in the spec). Parses
the DOS/PE headers, section table, and optional header without executing the
file. Non-PE files (and PE files ``pefile`` can't parse) degrade gracefully to
``{"available": False}``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore

_FUTURE_SKEW_SECONDS = 24 * 3600


def analyze_pe_headers(data: bytes) -> dict[str, Any]:
    """Return PE header facts, or ``{"available": False}`` for a non-PE file."""
    if pefile is None or data[:2] != b'MZ':
        return {'available': False}

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
        ])
    except Exception:  # noqa: BLE001 - malformed/hostile PE must not crash analysis
        return {'available': False}

    try:
        oh = pe.OPTIONAL_HEADER
        fh = pe.FILE_HEADER
        characteristics = fh.Characteristics

        timestamp = fh.TimeDateStamp
        timestamp_iso: str | None = None
        timestamp_suspicious = timestamp == 0
        if timestamp:
            try:
                dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                timestamp_iso = dt.isoformat()
                if dt.timestamp() > datetime.now(timezone.utc).timestamp() + _FUTURE_SKEW_SECONDS:
                    timestamp_suspicious = True
            except (OverflowError, OSError, ValueError):
                timestamp_suspicious = True

        dll_characteristics = getattr(oh, 'DllCharacteristics', 0)
        sections = []
        high_entropy = 0
        wx_count = 0
        for section in pe.sections:
            entropy = round(section.get_entropy(), 2)
            writable = bool(section.Characteristics & 0x80000000)
            executable = bool(section.Characteristics & 0x20000000)
            if entropy >= 7.0:
                high_entropy += 1
            if writable and executable:
                wx_count += 1
            sections.append({
                'name': section.Name.rstrip(b'\x00').decode('latin-1', 'replace'),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': entropy,
                'writable': writable,
                'executable': executable,
            })

        overlay_offset = pe.get_overlay_data_start_offset()
        overlay_bytes = max(len(data) - overlay_offset, 0) if overlay_offset is not None else 0

        return {
            'available': True,
            'is_dll': bool(characteristics & 0x2000),
            'is_exe': not bool(characteristics & 0x2000),
            'is_driver': bool(getattr(oh, 'Subsystem', 0) == 1 and characteristics & 0x2000),
            'machine': hex(fh.Machine),
            'subsystem': getattr(oh, 'Subsystem', None),
            'timestamp': timestamp_iso,
            'timestamp_suspicious': timestamp_suspicious,
            'num_sections': fh.NumberOfSections,
            'entry_point': hex(oh.AddressOfEntryPoint) if oh else None,
            'size_code': getattr(oh, 'SizeOfCode', None),
            'size_image': getattr(oh, 'SizeOfImage', None),
            'aslr': bool(dll_characteristics & 0x0040),
            'dep': bool(dll_characteristics & 0x0100),
            'no_seh': bool(dll_characteristics & 0x0400),
            'cfg': bool(dll_characteristics & 0x4000),
            'has_debug': pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size > 0 if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 6 else False,
            'has_tls': pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size > 0 if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 9 else False,
            'checksum_zero': oh.CheckSum == 0,
            'sections': sections,
            'high_entropy_section_count': high_entropy,
            'writable_executable_section_count': wx_count,
            'overlay_bytes': overlay_bytes,
        }
    except Exception:  # noqa: BLE001 - never let a malformed PE break analysis
        return {'available': False}
    finally:
        pe.close()
