from app.modules.file_analysis.analyzers.hashing import calculate_hashes
from app.modules.file_analysis.analyzers.signature_matching import match_signature


def test_signature_matching_with_real_hash():

    with open("sample.txt", "rb") as file:
        data = file.read()

    hashes = calculate_hashes(data)

    result = match_signature(hashes["sha256"])

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