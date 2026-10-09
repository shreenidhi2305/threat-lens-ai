"""Import table and API-call analysis for Windows executables.

Part of the Static Analysis Workflow ("Import and API call analysis" in the
spec). Reads the PE import table and buckets the imported function names into
capability categories -- the same categories the ML feature extractor uses,
kept as an independent, human-readable copy here so file analysis has no
dependency on the ``app.ml`` package.
"""

from __future__ import annotations

from typing import Any

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None  # type: ignore

_MAX_FUNCTIONS_SAMPLE = 60

# Import-name substrings grouped by capability (lower-cased match). Mirrors
# app.ml.features.extractor._IMPORT_CATEGORIES so the analyst-facing report and
# the ML model agree on what each category means.
IMPORT_CATEGORIES: dict[str, tuple[str, ...]] = {
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
        'outputdebugstring',
    ),
    'process_enum': ('createtoolhelp32snapshot', 'process32first', 'process32next', 'openprocess'),
    'file_ops': ('createfile', 'writefile', 'readfile', 'deletefile', 'movefile', 'copyfile'),
    'privilege': ('adjusttokenprivileges', 'lookupprivilegevalue', 'openprocesstoken'),
    'keylog': ('setwindowshookex', 'getasynckeystate', 'getkeyboardstate', 'getforegroundwindow'),
}


def _categorize(function_name: str) -> list[str]:
    lowered = function_name.lower()
    return [category for category, needles in IMPORT_CATEGORIES.items() if any(n in lowered for n in needles)]


def analyze_imports(data: bytes) -> dict[str, Any]:
    """Return the imported DLLs/functions and matched capability categories."""
    if pefile is None or data[:2] != b'MZ':
        return {'available': False, 'dlls': [], 'functions_sample': [], 'categories': {}}

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
        ])
    except Exception:  # noqa: BLE001 - malformed/hostile PE must not crash analysis
        return {'available': False, 'dlls': [], 'functions_sample': [], 'categories': {}}

    try:
        dlls: list[str] = []
        functions: list[str] = []
        categories: dict[str, list[str]] = {}

        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
            dll_name = entry.dll.decode('latin-1', 'replace') if entry.dll else 'unknown'
            dlls.append(dll_name)
            for imp in entry.imports:
                if not imp.name:
                    continue
                name = imp.name.decode('latin-1', 'replace')
                functions.append(name)
                for category in _categorize(name):
                    categories.setdefault(category, [])
                    if name not in categories[category]:
                        categories[category].append(name)

        return {
            'available': True,
            'dlls': sorted(set(dlls)),
            'function_count': len(functions),
            'functions_sample': sorted(set(functions))[:_MAX_FUNCTIONS_SAMPLE],
            'categories': categories,
        }
    except Exception:  # noqa: BLE001 - never let a malformed PE break analysis
        return {'available': False, 'dlls': [], 'functions_sample': [], 'categories': {}}
    finally:
        pe.close()
