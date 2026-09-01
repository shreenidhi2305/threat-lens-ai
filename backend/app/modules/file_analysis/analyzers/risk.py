"""Rule-based risk scoring and suspicious-indicator aggregation.

This is the deterministic "Static Analysis Output" from the spec: it turns the
individual analyzer results into a single 0-100 risk score, a human-readable
classification, and a suspicious-indicators report. It is intentionally *not*
machine learning -- the ML classifier is a later milestone and consumes these
same signals as features.
"""

import re

_SUSPICIOUS_STRING_PATTERNS: dict[str, re.Pattern[bytes]] = {
    'PowerShell execution': re.compile(rb'powershell|pwsh', re.IGNORECASE),
    'Encoded PowerShell command': re.compile(rb'-enc(odedcommand)?\b', re.IGNORECASE),
    'Command shell invocation': re.compile(rb'cmd\.exe\s*/c', re.IGNORECASE),
    'Script host (wscript/cscript)': re.compile(rb'\b[wc]script\.exe', re.IGNORECASE),
    'LOLBins (rundll32/regsvr32/mshta)': re.compile(rb'\b(rundll32|regsvr32|mshta)\b', re.IGNORECASE),
    'certutil download': re.compile(rb'certutil.{0,20}-urlcache', re.IGNORECASE),
    'Base64 decode': re.compile(rb'FromBase64String|base64\s+-d|certutil.{0,20}-decode', re.IGNORECASE),
    'Shadow copy deletion': re.compile(rb'vssadmin.{0,20}delete.{0,20}shadows', re.IGNORECASE),
    'Scheduled task creation': re.compile(rb'schtasks\s*/create', re.IGNORECASE),
    'Credential tooling': re.compile(rb'mimikatz|sekurlsa|lsass', re.IGNORECASE),
}

_SEVERITY_WEIGHT = {'high': 30, 'medium': 18, 'low': 8, 'info': 2}
_SIGNATURE_SEVERITY_WEIGHT = {'high': 75, 'medium': 45, 'low': 20, 'info': 5}
_YARA_TOTAL_CAP = 50

_LOW_MAX = 19
_MEDIUM_MAX = 59


def _classify(score: int, signature_match: dict, yara_matches: list[dict]) -> str:
    if signature_match.get('matched'):
        return f"Known {signature_match.get('type') or 'Malware'} ({signature_match['name']})"
    if score > _MEDIUM_MAX:
        family = next(
            (m['meta'].get('family') for m in yara_matches if m.get('meta', {}).get('family')),
            'Malware',
        )
        return f'Potential {family} Malware' if family != 'Malware' else 'Potential Malware'
    if score > _LOW_MAX:
        return 'Suspicious - Manual Review Recommended'
    return 'Likely Benign'


def _level(score: int) -> str:
    if score > _MEDIUM_MAX:
        return 'high'
    if score > _LOW_MAX:
        return 'medium'
    return 'low'


def _recommended_action(level: str) -> str:
    return {
        'high': 'Escalate to Security Analyst for investigation',
        'medium': 'Queue for analyst review',
        'low': 'No action required',
    }[level]


def find_suspicious_strings(data: bytes) -> list[str]:
    return [label for label, pattern in _SUSPICIOUS_STRING_PATTERNS.items() if pattern.search(data)]


def assess(
    *,
    data: bytes,
    metadata: dict,
    yara_matches: list[dict],
    signature_match: dict,
    network: dict,
) -> dict:
    """Aggregate all static signals into indicators + a risk assessment."""
    score = 0
    indicators: list[str] = []

    if signature_match.get('matched'):
        weight = _SIGNATURE_SEVERITY_WEIGHT.get(signature_match.get('severity') or 'high', 60)
        score += weight
        indicators.append(f"Known malware signature: {signature_match['name']}")

    yara_contribution = 0
    for match in yara_matches:
        severity = str(match.get('meta', {}).get('severity', 'low')).lower()
        yara_contribution += _SEVERITY_WEIGHT.get(severity, 8)
        description = match.get('meta', {}).get('description', match['rule'])
        indicators.append(f"YARA match: {match['rule']} - {description}")
    score += min(yara_contribution, _YARA_TOTAL_CAP)

    if metadata.get('extension_matches_content') is False:
        score += 20
        indicators.append(
            f"Extension '{metadata.get('extension')}' does not match detected content "
            f"({metadata.get('file_type')})"
        )

    if metadata.get('likely_packed'):
        score += 15
        indicators.append(
            f"High entropy ({metadata.get('shannon_entropy')}) - likely packed or encrypted"
        )

    if network.get('urls'):
        score += 10
        indicators.append(f"Embedded URL(s): {len(network['urls'])}")
    if network.get('ips'):
        score += 8
        indicators.append(f"Embedded public IP address(es): {len(network['ips'])}")

    suspicious_strings = find_suspicious_strings(data)
    if suspicious_strings:
        score += min(8 + 4 * len(suspicious_strings), 24)
        indicators.append('Suspicious command strings: ' + ', '.join(suspicious_strings))

    score = max(0, min(score, 100))
    level = _level(score)

    return {
        'suspicious_indicators': indicators,
        'suspicious_strings': suspicious_strings,
        'risk': {
            'score': score,
            'level': level,
            'classification': _classify(score, signature_match, yara_matches),
            'recommended_action': _recommended_action(level),
        },
    }
