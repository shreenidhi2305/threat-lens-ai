"""Verdict fusion: combine the static-rule engine and the ML model.

Both are mandatory inputs. This is the "Result Generation" step from the
architecture diagram. Neither engine is a fallback for the other: the final
score is a blend, with high-confidence signals from either side flooring it.
"""

from __future__ import annotations

from app.modules.file_analysis.schemas import AnalysisResult, MLPrediction, Verdict

# Blend weights when the ML model is available.
_W_ML = 0.55
_W_RULES = 0.45

_LOW_MAX = 24
_MED_MAX = 64


def _level(score: int) -> str:
    return 'high' if score > _MED_MAX else 'medium' if score > _LOW_MAX else 'low'


def _label(score: int) -> str:
    return 'malicious' if score > _MED_MAX else 'suspicious' if score > _LOW_MAX else 'benign'


def _action(level: str) -> str:
    return {
        'high': 'Escalate to Security Analyst for investigation',
        'medium': 'Queue for analyst review',
        'low': 'No action required',
    }[level]


def _high_severity_yara(result: AnalysisResult) -> int:
    return sum(1 for m in result.yara_matches if str(m.meta.get('severity', '')).lower() == 'high')


def fuse(result: AnalysisResult, ml: MLPrediction) -> Verdict:
    static_score = result.risk.score
    static_level = result.risk.level
    sig = result.signature_match
    high_yara = _high_severity_yara(result)

    ml_prob = ml.malware_probability if (ml.available and ml.malware_probability is not None) else None
    ml_malicious = bool(ml.malicious) if ml.available else None

    # 1. blended base score
    if ml_prob is not None:
        score = _W_ML * (ml_prob * 100) + _W_RULES * static_score
    else:
        score = float(static_score)

    # 2. high-confidence signals floor the score (either engine can raise it)
    floors: list[tuple[int, str]] = []
    if sig.matched:
        floors.append((92, f'signature:{sig.name}'))
    if ml_prob is not None and ml_prob >= 0.90:
        floors.append((82, 'ml:high-confidence'))
    if high_yara:
        floors.append((72, f'yara:{high_yara}-high-severity'))
    if ml_prob is not None and ml_prob >= 0.70 and static_score >= 40:
        floors.append((70, 'ml+rules:corroborated'))
    for value, _ in floors:
        score = max(score, value)

    score_int = int(round(min(max(score, 0), 100)))
    level = _level(score_int)
    label = _label(score_int)

    # 3. agreement between the two engines
    if ml_malicious is None:
        agreement = 'rules-only'
    elif ml_malicious and static_level in ('medium', 'high'):
        agreement = 'agree'
    elif not ml_malicious and static_level == 'low':
        agreement = 'agree'
    elif ml_malicious and static_level == 'low':
        agreement = 'ml-only'
    elif not ml_malicious and static_level == 'high':
        agreement = 'rules-only'
    else:
        agreement = 'ml-only' if ml_malicious else 'rules-only'
    # A genuine conflict: the rule engine has a strong opinion the model missed.
    if ml_prob is not None and ml_prob < 0.20 and (sig.matched or high_yara >= 2):
        agreement = 'conflict'

    # 4. family / category
    family: str | None = None
    if sig.matched and sig.type:
        family = sig.type
    elif ml.available and ml.malicious and (ml.category_confidence or 0) >= 0.35 and ml.category:
        family = ml.category.capitalize()
    else:
        family = next(
            (
                str(m.meta.get('family'))
                for m in result.yara_matches
                if m.meta.get('family') and str(m.meta['family']) not in
                ('Obfuscation', 'Packed', 'AntiAnalysis', 'DefenseEvasion', 'Persistence', 'Test')
            ),
            None,
        )

    # 5. human-readable classification
    contributors: list[str] = []
    if ml.available and ml_prob is not None:
        contributors.append(f'ML {ml_prob:.0%}')
    if sig.matched:
        contributors.append('signature match')
    if result.yara_matches:
        contributors.append(f'YARA {len(result.yara_matches)}')
    if label == 'benign':
        classification = 'Likely benign'
    elif family:
        classification = f'{family}' + (f'  ({", ".join(contributors)})' if contributors else '')
    elif label == 'malicious':
        classification = 'Malware' + (f'  ({", ".join(contributors)})' if contributors else '')
    else:
        classification = 'Suspicious' + (f'  ({", ".join(contributors)})' if contributors else '')

    # 6. confidence
    if agreement == 'agree':
        confidence = 0.80 + 0.15 * (abs(score_int - 45) / 55)
    elif agreement == 'conflict':
        confidence = 0.45
    else:
        confidence = 0.65
    confidence = round(min(confidence, 0.97), 2)

    return Verdict(
        label=label,
        score=score_int,
        level=level,
        confidence=confidence,
        classification=classification,
        family=family,
        recommended_action=_action(level),
        agreement=agreement,
        sources={
            'static_risk_score': static_score,
            'static_level': static_level,
            'signature_match': sig.name if sig.matched else None,
            'yara_rule_count': len(result.yara_matches),
            'yara_high_severity': high_yara,
            'ml_available': ml.available,
            'ml_probability': ml_prob,
            'ml_category': ml.category if ml.available else None,
            'ml_model_version': ml.model_versions.get('detector') if ml.available else None,
        },
    )
