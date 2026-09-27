"""Behavioral analysis, inferred from static artifacts (never from execution).

Milestone 3 "AI Prediction Module" calls for behavioral analysis. This platform
never runs the uploaded file, so behavior here means: what would this program
be capable of, based on the PE imports it calls, the YARA family tags it
matched, and the suspicious command strings found in it. Combines
``imports.py``, ``pe_analysis.py``, YARA metadata and the risk engine's string
matches into one capability list plus a short analyst-readable narrative.
"""

from __future__ import annotations

from typing import Any

from app.modules.file_analysis.analyzers.imports import analyze_imports
from app.modules.file_analysis.analyzers.pe_analysis import analyze_pe_headers

_CATEGORY_LABELS: dict[str, str] = {
    'proc_inject': 'Process injection',
    'dynamic_load': 'Dynamic library loading',
    'crypto': 'Cryptographic operations',
    'network': 'Network communication',
    'registry': 'Registry manipulation',
    'service': 'Service control',
    'anti_debug': 'Anti-debugging / anti-analysis',
    'process_enum': 'Process enumeration',
    'file_ops': 'File system operations',
    'privilege': 'Privilege escalation',
    'keylog': 'Keyboard / input monitoring',
}

# YARA family metadata that describes a capability rather than a malware name.
_YARA_FAMILY_LABELS: dict[str, str] = {
    'Downloader': 'Downloads and executes remote payloads',
    'Dropper': 'Drops additional files to disk',
    'Injector': 'Injects code into other processes',
    'Stealer': 'Harvests credentials or sensitive data',
    'Spyware': 'Monitors user activity',
    'Ransomware': 'Encrypts files for extortion',
    'Backdoor': 'Provides remote attacker access',
    'Beacon': 'Communicates with a command-and-control server',
    'WebShell': 'Provides remote code execution via a web server',
    'Obfuscation': 'Obfuscates its own code',
    'DefenseEvasion': 'Attempts to evade security tooling',
    'Persistence': 'Establishes persistence across reboots',
}


def analyze_behavior(
    data: bytes,
    *,
    yara_matches: list[dict] | None = None,
    suspicious_strings: list[str] | None = None,
    network: dict | None = None,
) -> dict[str, Any]:
    pe = analyze_pe_headers(data)
    imports = analyze_imports(data)
    yara_matches = yara_matches or []
    suspicious_strings = suspicious_strings or []
    network = network or {}

    capabilities: list[dict[str, Any]] = []

    for category, functions in (imports.get('categories') or {}).items():
        capabilities.append({
            'category': category,
            'label': _CATEGORY_LABELS.get(category, category.replace('_', ' ').title()),
            'evidence': [f'API import: {fn}' for fn in functions[:6]],
        })

    seen_families: set[str] = set()
    for match in yara_matches:
        family = match.get('meta', {}).get('family')
        if not family or family in seen_families or family not in _YARA_FAMILY_LABELS:
            continue
        seen_families.add(family)
        capabilities.append({
            'category': f'yara:{family}',
            'label': _YARA_FAMILY_LABELS[family],
            'evidence': [f'YARA rule: {match["rule"]}'],
        })

    if suspicious_strings:
        capabilities.append({
            'category': 'command_execution',
            'label': 'Command / script execution',
            'evidence': list(suspicious_strings[:6]),
        })

    if network.get('urls') or network.get('ips'):
        already = any(c['category'] == 'network' for c in capabilities)
        if not already:
            evidence = [f'Embedded URL: {u}' for u in (network.get('urls') or [])[:3]]
            evidence += [f'Embedded IP: {ip}' for ip in (network.get('ips') or [])[:3]]
            capabilities.append({
                'category': 'network',
                'label': _CATEGORY_LABELS['network'],
                'evidence': evidence,
            })

    if pe.get('available'):
        if pe.get('high_entropy_section_count'):
            capabilities.append({
                'category': 'packed_sections',
                'label': 'Packed or encrypted code sections',
                'evidence': [f'{pe["high_entropy_section_count"]} section(s) with entropy >= 7.0'],
            })
        if pe.get('writable_executable_section_count'):
            capabilities.append({
                'category': 'wx_sections',
                'label': 'Writable and executable memory sections',
                'evidence': [f'{pe["writable_executable_section_count"]} RWX section(s) - common in shellcode loaders'],
            })
        if pe.get('timestamp_suspicious'):
            capabilities.append({
                'category': 'suspicious_timestamp',
                'label': 'Forged or missing compile timestamp',
                'evidence': ['PE timestamp is zero or in the future'],
            })

    if capabilities:
        labels = [c['label'] for c in capabilities]
        if len(labels) == 1:
            narrative = f'Static analysis indicates this file is capable of: {labels[0].lower()}.'
        else:
            narrative = (
                'Static analysis indicates this file is capable of: '
                + ', '.join(label.lower() for label in labels[:-1])
                + f', and {labels[-1].lower()}.'
            )
    elif pe.get('available'):
        narrative = 'No suspicious capabilities were inferred from imports, YARA families, or strings.'
    else:
        narrative = 'No executable behavioral indicators were extracted (not a supported executable format).'

    return {
        'available': pe.get('available', False) or imports.get('available', False),
        'is_pe': bool(pe.get('available')),
        'capabilities': capabilities,
        'narrative': narrative,
        'pe_summary': pe if pe.get('available') else {},
        'import_summary': {
            'dll_count': len(imports.get('dlls') or []),
            'function_count': imports.get('function_count', 0),
            'dlls': imports.get('dlls') or [],
        } if imports.get('available') else {},
    }
