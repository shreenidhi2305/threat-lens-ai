import yara
from pathlib import Path


RULES_PATH = Path(__file__).parent / "yara_rules"


def scan_with_yara(data: bytes) -> list[dict]:
    rule_files = list(RULES_PATH.glob("*.yar"))

    if not rule_files:
        return []

    filepaths = {
        f"rule_{index}": str(rule_file)
        for index, rule_file in enumerate(rule_files)
    }

    rules = yara.compile(filepaths=filepaths)

    matches = rules.match(data=data)

    results = []

    for match in matches:
        results.append({
            "rule": match.rule,
            "namespace": match.namespace,
            "tags": list(match.tags),
            "meta": dict(match.meta),
        })

    return results