def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    output: list[str] = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
            continue
        if len(current) >= min_length:
            output.append(''.join(current))
        current = []
    if len(current) >= min_length:
        output.append(''.join(current))
    return output
