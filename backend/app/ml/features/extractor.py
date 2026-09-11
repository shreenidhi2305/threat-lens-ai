"""Unified static feature extractor for the ML prediction service.

Turns raw file bytes (plus, when available, the Milestone 1 static-analysis
result) into a fixed-length numeric vector. Works on any file: PE-specific
features are zero-filled when the sample is not a PE.

Everything here is our own code on top of ``pefile`` (MIT), ``numpy`` and the
Milestone 1 analyzers. No AGPL / EMBER code.

Public API:
    FEATURE_NAMES : list[str]              - ordered, stable feature names
    extract_features(data, analysis=None)  - -> np.ndarray[float32] of len(FEATURE_NAMES)
"""

from __future__ import annotations

import hashlib
import math

import numpy as np

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore

_BYTE_HIST_BINS = 256
_ENTROPY_HIST_BINS = 16
_ENTROPY_WINDOW = 2048
_IMPORT_HASH_BUCKETS = 24
_SECTIONNAME_HASH_BUCKETS = 8

# Import-name substrings grouped by capability (lower-cased match).
_IMPORT_CATEGORIES: dict[str, tuple[str, ...]] = {
    'proc_inject': (
        'virtualalloc', 'virtualprotect', 'writeprocessmemory', 'createremotethread',
        'ntunmapviewofsection', 'setthreadcontext', 'queueuserapc', 'mapviewofsection',
        'ntcreatethreadex', 'rtlcreateuserthread',
    ),
    'dynamic_load': ('loadlibrary', 'getprocaddress', 'ldrloaddll', 'getmodulehandle'),
    'crypto': ('crypt', 'bcrypt', 'cryptacquirecontext', 'cryptencrypt', 'cryptdecrypt'),
    'network': (
        'wsastartup', 'socket', 'connect', 'send', 'recv', 'internetopen', 'internetconnect',
        'httpsendrequest', 'winhttp', 'urldownloadtofile', 'gethostbyname',
    ),
    'registry': ('regopenkey', 'regsetvalue', 'regcreatekey', 'regqueryvalue', 'regdeletekey'),
    'service': ('openscmanager', 'createservice', 'startservice', 'controlservice'),
    'anti_debug': (
        'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
        'outputdebugstring', 'gettickcount', 'queryperformancecounter',
    ),
    'process_enum': ('createtoolhelp32snapshot', 'process32first', 'process32next', 'openprocess'),
    'file_ops': ('createfile', 'writefile', 'readfile', 'deletefile', 'movefile', 'copyfile'),
    'privilege': ('adjusttokenprivileges', 'lookupprivilegevalue', 'openprocesstoken'),
    'keylog': ('setwindowshookex', 'getasynckeystate', 'getkeyboardstate', 'getforegroundwindow'),
}

# Suspicious tokens looked for in the extracted ASCII strings.
_SUSPICIOUS_STRING_TOKENS: tuple[str, ...] = (
    b'powershell', b'cmd.exe', b'/c ', b'-encodedcommand', b'-nop', b'-w hidden',
    b'downloadstring', b'downloadfile', b'webclient', b'certutil', b'bitsadmin',
    b'schtasks', b'reg add', b'vssadmin', b'wscript', b'cscript', b'rundll32',
    b'regsvr32', b'mshta', b'amsi', b'mimikatz', b'lsass', b'base64', b'invoke-expression',
    b'\\currentversion\\run', b'.onion', b'cobaltstrike', b'meterpreter',
)

_YARA_FAMILY_FLAGS: tuple[str, ...] = (
    'Downloader', 'Dropper', 'Injector', 'Stealer', 'Spyware', 'Ransomware',
    'Backdoor', 'Beacon', 'WebShell', 'Obfuscation', 'DefenseEvasion', 'Persistence',
)

_DOS_STUB = b'This program cannot be run in DOS mode'


# --------------------------------------------------------------------------- #
#  low-level helpers
# --------------------------------------------------------------------------- #

def _shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = np.bincount(np.frombuffer(buf, dtype=np.uint8), minlength=256).astype(np.float64)
    probs = counts[counts > 0] / len(buf)
    return float(-(probs * np.log2(probs)).sum())


def _byte_histogram(data: bytes) -> np.ndarray:
    if not data:
        return np.zeros(_BYTE_HIST_BINS, dtype=np.float32)
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=_BYTE_HIST_BINS)
    return (counts / counts.sum()).astype(np.float32)


def _entropy_histogram(data: bytes) -> np.ndarray:
    """Histogram of per-window Shannon entropy across the file."""
    if len(data) < _ENTROPY_WINDOW:
        windows = [data] if data else []
    else:
        windows = [
            data[i : i + _ENTROPY_WINDOW]
            for i in range(0, len(data) - _ENTROPY_WINDOW + 1, _ENTROPY_WINDOW)
        ]
    if not windows:
        return np.zeros(_ENTROPY_HIST_BINS, dtype=np.float32)
    entropies = np.array([_shannon_entropy(w) for w in windows])
    hist, _ = np.histogram(entropies, bins=_ENTROPY_HIST_BINS, range=(0.0, 8.0))
    return (hist / hist.sum()).astype(np.float32)


def _ascii_strings(data: bytes, min_len: int = 5) -> list[bytes]:
    out: list[bytes] = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur))
            cur.clear()
    if len(cur) >= min_len:
        out.append(bytes(cur))
    return out


def _hash_bucket(text: str, buckets: int) -> int:
    return int.from_bytes(hashlib.md5(text.encode('utf-8', 'ignore')).digest()[:4], 'little') % buckets


# --------------------------------------------------------------------------- #
#  feature groups
# --------------------------------------------------------------------------- #

def _general_features(data: bytes) -> dict[str, float]:
    n = len(data)
    head = data[:8192]
    printable = sum(1 for b in head if 32 <= b <= 126 or b in (9, 10, 13))
    nulls = head.count(0)
    return {
        'size_log': math.log1p(n),
        'entropy': _shannon_entropy(data),
        'printable_ratio': printable / len(head) if head else 0.0,
        'null_ratio': nulls / len(head) if head else 0.0,
        'has_mz': float(data[:2] == b'MZ'),
        'has_pe_stub': float(_DOS_STUB in data[:4096]),
        'is_elf': float(data[:4] == b'\x7fELF'),
        'is_ole': float(data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'),
        'is_pdf': float(data[:5] == b'%PDF-'),
        'is_zip': float(data[:4] == b'PK\x03\x04'),
        'is_script_shebang': float(data[:2] == b'#!'),
        'mz_count': float(min(data.count(b'MZ'), 50)) / 50.0,
    }


def _string_features(data: bytes) -> dict[str, float]:
    strings = _ascii_strings(data)
    total = len(strings)
    joined = b'\n'.join(strings)
    lengths = np.array([len(s) for s in strings]) if strings else np.array([0])
    lowered = joined.lower()

    url_count = lowered.count(b'http://') + lowered.count(b'https://') + lowered.count(b'ftp://')
    reg_count = lowered.count(b'hkey_') + lowered.count(b'hkcu\\') + lowered.count(b'hklm\\')
    path_count = lowered.count(b'c:\\') + lowered.count(b'\\windows\\') + lowered.count(b'/usr/')
    susp = sum(lowered.count(tok) for tok in _SUSPICIOUS_STRING_TOKENS)

    return {
        'str_count_log': math.log1p(total),
        'str_len_mean': float(lengths.mean()),
        'str_len_max': float(lengths.max()),
        'str_bytes_ratio': len(joined) / len(data) if data else 0.0,
        'str_entropy': _shannon_entropy(joined),
        'str_url_count': math.log1p(url_count),
        'str_registry_count': math.log1p(reg_count),
        'str_path_count': math.log1p(path_count),
        'str_suspicious_tokens': math.log1p(susp),
        'str_has_onion': float(b'.onion' in lowered),
    }


def _empty_pe_features() -> dict[str, float]:
    feats = {
        'pe_is_pe': 0.0,
        'pe_machine_amd64': 0.0, 'pe_machine_i386': 0.0,
        'pe_subsystem_gui': 0.0, 'pe_subsystem_cui': 0.0,
        'pe_is_dll': 0.0, 'pe_is_exe': 0.0, 'pe_is_driver': 0.0,
        'pe_timestamp_log': 0.0, 'pe_timestamp_zero': 0.0, 'pe_timestamp_future': 0.0,
        'pe_num_sections': 0.0,
        'pe_size_code_log': 0.0, 'pe_size_initdata_log': 0.0, 'pe_size_uninitdata_log': 0.0,
        'pe_entrypoint_log': 0.0, 'pe_imagebase_log': 0.0,
        'pe_num_rva': 0.0,
        'pe_has_debug': 0.0, 'pe_has_tls': 0.0, 'pe_has_resources': 0.0,
        'pe_has_relocs': 0.0, 'pe_has_security': 0.0, 'pe_has_exports': 0.0,
        'pe_num_imported_dlls': 0.0, 'pe_num_imported_funcs_log': 0.0, 'pe_num_exports_log': 0.0,
        'pe_checksum_zero': 0.0, 'pe_checksum_mismatch': 0.0,
        'pe_overlay_ratio': 0.0,
        'pe_aslr': 0.0, 'pe_dep': 0.0, 'pe_no_seh': 0.0, 'pe_cfg': 0.0,
        'pe_sec_entropy_mean': 0.0, 'pe_sec_entropy_max': 0.0, 'pe_sec_entropy_min': 0.0,
        'pe_sec_high_entropy_count': 0.0,
        'pe_sec_wx_count': 0.0, 'pe_sec_vsize_gt_rawsize': 0.0,
        'pe_sec_zero_rawsize': 0.0, 'pe_sec_nonstandard_names': 0.0,
        'pe_ep_section_entropy': 0.0, 'pe_ep_section_writable': 0.0, 'pe_ep_in_last_section': 0.0,
    }
    for cat in _IMPORT_CATEGORIES:
        feats[f'pe_imp_{cat}'] = 0.0
    for i in range(_IMPORT_HASH_BUCKETS):
        feats[f'pe_imphash_b{i}'] = 0.0
    for i in range(_SECTIONNAME_HASH_BUCKETS):
        feats[f'pe_secname_b{i}'] = 0.0
    return feats


_STD_SECTION_NAMES = {
    '.text', '.data', '.rdata', '.bss', '.idata', '.edata', '.pdata', '.rsrc',
    '.reloc', '.tls', '.debug', '.CRT', '.gfids', 'INIT', 'PAGE', '.00cfg',
}


def _pe_features(data: bytes) -> dict[str, float]:
    feats = _empty_pe_features()
    if pefile is None or data[:2] != b'MZ':
        return feats
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'],
            ]
        )
    except Exception:  # noqa: BLE001 - malformed PE: keep the zero-filled features
        return feats

    feats['pe_is_pe'] = 1.0
    try:
        _fill_pe_features(pe, data, feats)
    except Exception:  # noqa: BLE001 - malformed field: keep whatever we filled
        pass
    pe.close()
    return feats


def _data_dir(oh, name: str):
    idx = pefile.DIRECTORY_ENTRY[name]
    return oh.DATA_DIRECTORY[idx] if idx < len(oh.DATA_DIRECTORY) else None


def _fill_pe_features(pe, data: bytes, feats: dict[str, float]) -> None:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    feats['pe_machine_amd64'] = float(fh.Machine == 0x8664)
    feats['pe_machine_i386'] = float(fh.Machine == 0x14C)
    ch = fh.Characteristics
    feats['pe_is_dll'] = float(bool(ch & 0x2000))
    feats['pe_is_exe'] = float(bool(ch & 0x0002) and not (ch & 0x2000))
    feats['pe_is_driver'] = float(oh.Subsystem == 1)
    feats['pe_subsystem_gui'] = float(oh.Subsystem == 2)
    feats['pe_subsystem_cui'] = float(oh.Subsystem == 3)

    ts = fh.TimeDateStamp
    feats['pe_timestamp_log'] = math.log1p(ts)
    feats['pe_timestamp_zero'] = float(ts == 0)
    feats['pe_timestamp_future'] = float(ts > 1_900_000_000)

    feats['pe_num_sections'] = float(fh.NumberOfSections)
    feats['pe_size_code_log'] = math.log1p(oh.SizeOfCode)
    feats['pe_size_initdata_log'] = math.log1p(oh.SizeOfInitializedData)
    feats['pe_size_uninitdata_log'] = math.log1p(oh.SizeOfUninitializedData)
    feats['pe_entrypoint_log'] = math.log1p(oh.AddressOfEntryPoint)
    feats['pe_imagebase_log'] = math.log1p(oh.ImageBase)
    feats['pe_num_rva'] = float(oh.NumberOfRvaAndSizes)

    dc = oh.DllCharacteristics
    feats['pe_aslr'] = float(bool(dc & 0x0040))
    feats['pe_dep'] = float(bool(dc & 0x0100))
    feats['pe_no_seh'] = float(bool(dc & 0x0400))
    feats['pe_cfg'] = float(bool(dc & 0x4000))

    feats['pe_has_debug'] = float(hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and bool(pe.DIRECTORY_ENTRY_DEBUG))
    feats['pe_has_tls'] = float(hasattr(pe, 'DIRECTORY_ENTRY_TLS'))
    feats['pe_has_resources'] = float(hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'))
    feats['pe_has_relocs'] = float(hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'))
    sec_dir = _data_dir(oh, 'IMAGE_DIRECTORY_ENTRY_SECURITY')
    feats['pe_has_security'] = float(
        sec_dir is not None and sec_dir.VirtualAddress != 0 and sec_dir.Size != 0
    )

    try:
        feats['pe_checksum_zero'] = float(oh.CheckSum == 0)
        feats['pe_checksum_mismatch'] = float(oh.CheckSum != 0 and oh.CheckSum != pe.generate_checksum())
    except Exception:  # noqa: BLE001
        pass

    # sections
    entropies, wx, vgtr, zraw, nonstd = [], 0, 0, 0, 0
    last_section_end = 0
    for section in pe.sections:
        e = section.get_entropy()
        entropies.append(e)
        flags = section.Characteristics
        if (flags & 0x20000000) and (flags & 0x80000000):
            wx += 1
        if section.Misc_VirtualSize > section.SizeOfRawData * 2 and section.SizeOfRawData > 0:
            vgtr += 1
        if section.SizeOfRawData == 0:
            zraw += 1
        name = section.Name.rstrip(b'\x00').decode('latin-1', 'ignore')
        if name and name not in _STD_SECTION_NAMES:
            nonstd += 1
            feats[f'pe_secname_b{_hash_bucket(name, _SECTIONNAME_HASH_BUCKETS)}'] += 1.0
        last_section_end = max(last_section_end, section.PointerToRawData + section.SizeOfRawData)

    if entropies:
        feats['pe_sec_entropy_mean'] = float(np.mean(entropies))
        feats['pe_sec_entropy_max'] = float(np.max(entropies))
        feats['pe_sec_entropy_min'] = float(np.min(entropies))
        feats['pe_sec_high_entropy_count'] = float(sum(1 for e in entropies if e > 7.0))
    feats['pe_sec_wx_count'] = float(wx)
    feats['pe_sec_vsize_gt_rawsize'] = float(vgtr)
    feats['pe_sec_zero_rawsize'] = float(zraw)
    feats['pe_sec_nonstandard_names'] = float(nonstd)
    feats['pe_overlay_ratio'] = (len(data) - last_section_end) / len(data) if last_section_end and data else 0.0

    # entry-point section
    try:
        ep = oh.AddressOfEntryPoint
        ep_section = pe.get_section_by_rva(ep)
        if ep_section is not None:
            feats['pe_ep_section_entropy'] = float(ep_section.get_entropy())
            feats['pe_ep_section_writable'] = float(bool(ep_section.Characteristics & 0x80000000))
            feats['pe_ep_in_last_section'] = float(ep_section == pe.sections[-1])
    except Exception:  # noqa: BLE001
        pass

    # imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        dll_count = 0
        func_count = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_count += 1
            dll_name = (entry.dll or b'').decode('latin-1', 'ignore').lower()
            for imp in entry.imports:
                func_count += 1
                fname = (imp.name or b'').decode('latin-1', 'ignore').lower()
                if not fname:
                    continue
                feats[f'pe_imphash_b{_hash_bucket(dll_name + "!" + fname, _IMPORT_HASH_BUCKETS)}'] += 1.0
                for cat, needles in _IMPORT_CATEGORIES.items():
                    if any(nd in fname for nd in needles):
                        feats[f'pe_imp_{cat}'] += 1.0
        feats['pe_num_imported_dlls'] = float(dll_count)
        feats['pe_num_imported_funcs_log'] = math.log1p(func_count)

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT.symbols:
        feats['pe_has_exports'] = 1.0
        feats['pe_num_exports_log'] = math.log1p(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))


def _analysis_features(analysis: dict | None) -> dict[str, float]:
    """Signals from the Milestone 1 static-analysis result (rule engine)."""
    feats = {
        'sa_available': 0.0,
        'sa_risk_score': 0.0,
        'sa_signature_matched': 0.0,
        'sa_yara_total': 0.0,
        'sa_yara_high': 0.0,
        'sa_yara_medium': 0.0,
        'sa_yara_low': 0.0,
        'sa_num_urls': 0.0,
        'sa_num_ips': 0.0,
        'sa_num_domains': 0.0,
        'sa_num_suspicious_strings': 0.0,
        'sa_extension_mismatch': 0.0,
        'sa_likely_packed': 0.0,
    }
    for fam in _YARA_FAMILY_FLAGS:
        feats[f'sa_yara_fam_{fam.lower()}'] = 0.0
    if not analysis:
        return feats

    feats['sa_available'] = 1.0
    risk = analysis.get('risk') or {}
    feats['sa_risk_score'] = float(risk.get('score', 0)) / 100.0
    feats['sa_signature_matched'] = float(bool((analysis.get('signature_match') or {}).get('matched')))

    yara = analysis.get('yara_matches') or []
    feats['sa_yara_total'] = float(len(yara))
    for m in yara:
        meta = m.get('meta', {}) if isinstance(m, dict) else {}
        sev = str(meta.get('severity', 'low')).lower()
        if sev in ('high', 'medium', 'low'):
            feats[f'sa_yara_{sev}'] += 1.0
        fam = str(meta.get('family', ''))
        key = f'sa_yara_fam_{fam.lower()}'
        if key in feats:
            feats[key] = 1.0

    net = analysis.get('network_indicators') or {}
    feats['sa_num_urls'] = float(len(net.get('urls', [])))
    feats['sa_num_ips'] = float(len(net.get('ips', [])))
    feats['sa_num_domains'] = float(len(net.get('domains', [])))
    feats['sa_num_suspicious_strings'] = float(len(analysis.get('suspicious_strings', [])))

    meta = analysis.get('metadata') or {}
    feats['sa_extension_mismatch'] = float(meta.get('extension_matches_content') is False)
    feats['sa_likely_packed'] = float(bool(meta.get('likely_packed')))
    return feats


# --------------------------------------------------------------------------- #
#  assembly
# --------------------------------------------------------------------------- #

def _build_feature_names() -> list[str]:
    names: list[str] = []
    names += [f'byte_{i}' for i in range(_BYTE_HIST_BINS)]
    names += [f'entropy_bin_{i}' for i in range(_ENTROPY_HIST_BINS)]
    names += list(_general_features(b'').keys())
    names += list(_string_features(b'').keys())
    names += list(_empty_pe_features().keys())
    names += list(_analysis_features(None).keys())
    return names


FEATURE_NAMES: list[str] = _build_feature_names()
FEATURE_COUNT: int = len(FEATURE_NAMES)


def extract_features(data: bytes, analysis: dict | None = None) -> np.ndarray:
    """Return the ordered feature vector for ``data`` as float32."""
    parts: dict[str, float] = {}
    parts.update(_general_features(data))
    parts.update(_string_features(data))
    parts.update(_pe_features(data))
    parts.update(_analysis_features(analysis))

    vec = np.concatenate(
        [
            _byte_histogram(data),
            _entropy_histogram(data),
            np.array([parts[name] for name in FEATURE_NAMES[_BYTE_HIST_BINS + _ENTROPY_HIST_BINS :]],
                     dtype=np.float32),
        ]
    ).astype(np.float32)
    vec[~np.isfinite(vec)] = 0.0
    return vec


class FeatureExtractor:
    """Thin object wrapper kept for the pipeline's dependency style."""

    feature_names = FEATURE_NAMES
    feature_count = FEATURE_COUNT

    def extract(self, data: bytes, analysis: dict | None = None) -> np.ndarray:
        return extract_features(data, analysis)


feature_extractor = FeatureExtractor()
