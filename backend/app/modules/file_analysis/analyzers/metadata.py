def extract_metadata(data: bytes) -> dict[str, str | int]:
    return {'size': len(data), 'type': 'unknown'}
