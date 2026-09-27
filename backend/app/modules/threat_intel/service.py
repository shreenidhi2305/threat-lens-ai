"""Threat-intelligence enrichment via the VirusTotal API.

Milestone 3 "AI Prediction Module" / "Threat intelligence workflows" from the
spec. This looks up a sample's SHA-256 against VirusTotal's community
verdicts -- a hash lookup only, the file itself is never uploaded anywhere.

Purely informational: a missing API key, a network error, or a timeout all
degrade to ``ThreatIntelResult(configured=False|available=False)`` and never
raise, so the detection pipeline's outcome never depends on a third party.
"""

from __future__ import annotations

import logging

import requests

from app.core.config import settings
from app.modules.file_analysis.schemas import ThreatIntelResult

logger = logging.getLogger(__name__)

_VT_FILE_URL = 'https://www.virustotal.com/api/v3/files/{sha256}'


class ThreatIntelService:
    def lookup_hash(self, sha256: str) -> ThreatIntelResult:
        if not settings.virustotal_configured:
            return ThreatIntelResult(configured=False, available=False, reason='VirusTotal API key not configured')

        try:
            response = requests.get(
                _VT_FILE_URL.format(sha256=sha256),
                headers={'x-apikey': settings.VIRUSTOTAL_API_KEY},
                timeout=settings.VIRUSTOTAL_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            logger.warning('VirusTotal lookup failed for %s: %s', sha256, exc)
            return ThreatIntelResult(configured=True, available=False, reason='VirusTotal request failed')

        if response.status_code == 404:
            return ThreatIntelResult(configured=True, available=False, reason='Hash not seen by VirusTotal')
        if response.status_code == 429:
            return ThreatIntelResult(configured=True, available=False, reason='VirusTotal rate limit reached')
        if response.status_code != 200:
            return ThreatIntelResult(
                configured=True, available=False, reason=f'VirusTotal returned HTTP {response.status_code}'
            )

        try:
            attributes = response.json()['data']['attributes']
            stats = attributes.get('last_analysis_stats', {})
            malicious = int(stats.get('malicious', 0))
            suspicious = int(stats.get('suspicious', 0))
            undetected = int(stats.get('undetected', 0))
            harmless = int(stats.get('harmless', 0))
            total = malicious + suspicious + undetected + harmless
            return ThreatIntelResult(
                configured=True,
                available=True,
                malicious=malicious,
                suspicious=suspicious,
                undetected=undetected,
                harmless=harmless,
                total_engines=total,
                reputation=attributes.get('reputation'),
                permalink=f'https://www.virustotal.com/gui/file/{sha256}',
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning('Could not parse VirusTotal response for %s: %s', sha256, exc)
            return ThreatIntelResult(configured=True, available=False, reason='Unexpected VirusTotal response shape')


threat_intel_service = ThreatIntelService()
