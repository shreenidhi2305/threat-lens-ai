"""Behavioral analysis service (static, no execution).

Wraps the engine and produces the API schema.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from app.modules.behavioral_analysis.engine import (
    attack_chain,
    compute_behavioral_risk,
    evaluate_behaviors,
    kill_chain_stage,
    summarize,
    tactics_summary,
)
from app.modules.behavioral_analysis.schemas import (
    BehavioralAnalysisResult,
    BehavioralFinding,
    BehaviorEvidence,
    TacticSummary,
)


class BehavioralAnalysisService:
    def analyze(
        self,
        data: bytes,
        *,
        object_path: str | None = None,
        suspicious_strings: list[str] | None = None,
        yara_matches: list[dict] | None = None,
        network: dict | None = None,
        metadata: dict | None = None,
        signature_match: dict | None = None,
        strings_sample: list[str] | None = None,
        file_hash: str | None = None,
    ) -> BehavioralAnalysisResult:
        if file_hash is None and data:
            file_hash = hashlib.sha256(data).hexdigest()

        behaviors_raw = evaluate_behaviors(
            data,
            suspicious_strings=suspicious_strings,
            yara_matches=yara_matches,
            network=network,
            metadata=metadata,
            signature_match=signature_match,
            strings_sample=strings_sample,
        )

        risk_score, risk_level, confidence = compute_behavioral_risk(behaviors_raw)

        # Build typed findings
        findings: list[BehavioralFinding] = []
        for raw in behaviors_raw:
            findings.append(
                BehavioralFinding(
                    id=raw["id"],
                    tactic=raw["tactic"],
                    tactic_id=raw.get("tactic_id", ""),
                    technique=raw["technique"],
                    technique_id=raw["technique_id"],
                    name=raw["name"],
                    description=raw["description"],
                    severity=raw["severity"],
                    confidence=raw["confidence"],
                    observed=raw["observed"],
                    evidence=[BehaviorEvidence(**e) for e in raw["evidence"]],
                    mitre_url=raw.get("mitre_url"),
                    risk_contribution=raw["risk_contribution"],
                )
            )

        # Only keep observed for external consumers by default? Keep all for completeness but report counts
        # We'll keep all but the router can filter if desired. Here we keep all for full matrix.
        tactic_summ = [TacticSummary(**t) for t in tactics_summary(behaviors_raw)]
        techniques = sorted({f.technique_id for f in findings if f.observed})
        chain = attack_chain(behaviors_raw)
        stage = kill_chain_stage(behaviors_raw)
        summary_text = summarize(behaviors_raw, risk_level)
        detected = sum(1 for f in findings if f.observed)

        return BehavioralAnalysisResult(
            generated_at=datetime.now(timezone.utc),
            file_hash=file_hash,
            object_path=object_path,
            risk_score=risk_score,
            risk_level=risk_level,  # type: ignore[arg-type]
            confidence=confidence,
            behaviors_detected=detected,
            behaviors_total=len(findings),
            behaviors=findings,
            tactics_summary=tactic_summ,
            technique_coverage=techniques,
            attack_chain=chain,
            summary=summary_text,
            kill_chain_stage=stage,
        )

    def analyze_from_analysis_result(self, analysis_result) -> BehavioralAnalysisResult:
        """Convenience: build behavioral result from a file_analysis AnalysisResult object or dict."""
        if isinstance(analysis_result, dict):
            data = analysis_result.get("_raw_bytes") or b""
            object_path = analysis_result.get("object_path")
            md = analysis_result.get("metadata") or {}
            if hasattr(md, "model_dump"):
                md = md.model_dump()
            elif not isinstance(md, dict):
                md = dict(md) if md else {}
            yara = analysis_result.get("yara_matches") or []
            if yara and isinstance(yara[0], dict) is False:
                # Pydantic objects
                yara = [m.model_dump() if hasattr(m, "model_dump") else dict(m) for m in yara]
            network = analysis_result.get("network_indicators") or {}
            if hasattr(network, "model_dump"):
                network = network.model_dump()
            elif not isinstance(network, dict):
                network = dict(network) if network else {}
            sig = analysis_result.get("signature_match") or {}
            if hasattr(sig, "model_dump"):
                sig = sig.model_dump()
            elif not isinstance(sig, dict):
                sig = dict(sig) if sig else {}
            suspicious = analysis_result.get("suspicious_strings") or []
            strings_sample = analysis_result.get("strings_sample") or []
            sha = analysis_result.get("sha256") or analysis_result.get("hashes", {}).get("sha256") if isinstance(analysis_result.get("hashes"), dict) else None
            if hasattr(analysis_result.get("hashes"), "sha256"):
                sha = analysis_result.get("hashes").sha256  # type: ignore
        else:
            # Pydantic AnalysisResult
            # Try to recover raw bytes from storage if available; else empty bytes still yields useful signal from structured fields
            data = b""
            try:
                from app.modules.file_analysis import storage

                loaded = storage.load_sample(analysis_result.object_path)  # type: ignore
                if loaded:
                    data = loaded
            except Exception:
                pass
            object_path = getattr(analysis_result, "object_path", None)
            md_obj = getattr(analysis_result, "metadata", None)
            md = md_obj.model_dump() if md_obj and hasattr(md_obj, "model_dump") else (dict(md_obj) if md_obj else {})
            yara_objs = getattr(analysis_result, "yara_matches", []) or []
            yara = [m.model_dump() if hasattr(m, "model_dump") else dict(m) for m in yara_objs]
            net_obj = getattr(analysis_result, "network_indicators", None)
            network = net_obj.model_dump() if net_obj and hasattr(net_obj, "model_dump") else (dict(net_obj) if net_obj else {})
            sig_obj = getattr(analysis_result, "signature_match", None)
            sig = sig_obj.model_dump() if sig_obj and hasattr(sig_obj, "model_dump") else (dict(sig_obj) if sig_obj else {})
            suspicious = getattr(analysis_result, "suspicious_strings", []) or []
            strings_sample = getattr(analysis_result, "strings_sample", []) or []
            sha = getattr(analysis_result, "sha256", None)

        return self.analyze(
            data,
            object_path=object_path,
            suspicious_strings=list(suspicious) if suspicious else None,
            yara_matches=list(yara) if yara else None,
            network=dict(network) if network else None,
            metadata=dict(md) if md else None,
            signature_match=dict(sig) if sig else None,
            strings_sample=list(strings_sample) if strings_sample else None,
            file_hash=sha,
        )


behavioral_analysis_service = BehavioralAnalysisService()
