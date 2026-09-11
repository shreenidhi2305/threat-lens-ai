from app.modules.file_analysis.analyzers.hashing import calculate_hashes
from app.modules.file_analysis.analyzers.signature_matching import match_signature


def test_signature_matching_with_real_hash():

    data = b"ThreatLens AI signature matching test"

    hashes = calculate_hashes(data)

    result = match_signature(hashes["sha256"])

    assert result["matched"] is False


def test_known_signature():

    result = match_signature(
        "fde90b1cbae13e703154c46f51b09c0f30e744659c1931c798104f933e4abb93"
    )

    assert result["matched"] is True
    assert result["name"] == "Test.Trojan"
    assert result["type"] == "Trojan"


def test_unknown_signature():

    result = match_signature(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )

    assert result["matched"] is False
    assert result["name"] is None
    assert result["type"] is None