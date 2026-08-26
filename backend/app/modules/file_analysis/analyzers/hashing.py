import hashlib


def calculate_hashes(data: bytes) -> dict[str, str]:
    return {
        'sha256': hashlib.sha256(data).hexdigest(),
        'md5': hashlib.md5(data).hexdigest(),
    }
