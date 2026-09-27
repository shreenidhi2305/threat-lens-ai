"""Milestone 3: static behavioral analysis (imports, PE structure, YARA/strings)."""

from app.modules.file_analysis.analyzers.behavior import analyze_behavior
from app.modules.file_analysis.analyzers.imports import _categorize, analyze_imports
from app.modules.file_analysis.analyzers.pe_analysis import analyze_pe_headers
from app.modules.file_analysis.service import file_analysis_service

PE_BYTES = b"MZ" + b"\x00" * 0x3A + (0x40).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 200
NOT_A_PE = b"just a plain text file, nothing executable here " * 5


def test_pe_headers_unavailable_for_non_pe():
    result = analyze_pe_headers(NOT_A_PE)
    assert result == {"available": False}


def test_imports_unavailable_for_non_pe():
    result = analyze_imports(NOT_A_PE)
    assert result["available"] is False
    assert result["dlls"] == []


def test_import_categorization_matches_known_capabilities():
    assert "proc_inject" in _categorize("VirtualAllocEx")
    assert "dynamic_load" in _categorize("LoadLibraryA")
    assert "network" in _categorize("InternetOpenUrlA")
    assert _categorize("SomeHarmlessFunction") == []


def test_behavior_narrative_flags_command_execution():
    behavior = analyze_behavior(
        NOT_A_PE,
        suspicious_strings=["PowerShell execution", "Base64 decode"],
    )
    categories = [c["category"] for c in behavior["capabilities"]]
    assert "command_execution" in categories
    assert "PowerShell execution" in behavior["narrative"].lower() or "command" in behavior["narrative"].lower()


def test_behavior_narrative_flags_yara_family():
    yara_matches = [{"rule": "Demo_Backdoor", "meta": {"family": "Backdoor"}}]
    behavior = analyze_behavior(NOT_A_PE, yara_matches=yara_matches)
    labels = [c["label"] for c in behavior["capabilities"]]
    assert any("remote attacker access" in label.lower() for label in labels)


def test_behavior_narrative_flags_network_indicators():
    behavior = analyze_behavior(NOT_A_PE, network={"urls": ["http://evil.example/a"], "ips": []})
    categories = [c["category"] for c in behavior["capabilities"]]
    assert "network" in categories


def test_behavior_narrative_empty_when_no_signals():
    behavior = analyze_behavior(NOT_A_PE)
    assert behavior["capabilities"] == []
    assert "No executable behavioral indicators" in behavior["narrative"]


def test_static_analysis_result_includes_behavior_profile():
    result = file_analysis_service.analyze_static_file("sample.txt", NOT_A_PE)
    assert result.behavior is not None
    assert result.behavior.is_pe is False


def test_static_analysis_result_behavior_for_pe_stub():
    result = file_analysis_service.analyze_static_file("sample.exe", PE_BYTES)
    # A bare DOS/PE stub with no sections/imports: pe_analysis should still parse
    # or gracefully decline, but never raise.
    assert result.behavior is not None
