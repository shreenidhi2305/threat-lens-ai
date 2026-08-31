KNOWN_SIGNATURES = {
    "fde90b1cbae13e703154c46f51b09c0f30e744659c1931c798104f933e4abb93": {
        "name": "Test.Trojan",
        "type": "Trojan",
    }
}


def match_signature(sha256: str) -> dict:
    signature = KNOWN_SIGNATURES.get(sha256)

    if signature:
        return {
            "matched": True,
            "name": signature["name"],
            "type": signature["type"],
        }

    return {
        "matched": False,
        "name": None,
        "type": None,
    }