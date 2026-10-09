import functools
import re


@functools.lru_cache(maxsize=8)
def _pattern(min_length: int) -> re.Pattern[bytes]:
    return re.compile(rb'[\x20-\x7e]{%d,}' % max(1, min_length))


def extract_strings(data: bytes, min_length: int = 4, limit: int | None = None) -> list[str]:
    """Printable-ASCII runs of at least ``min_length`` bytes, in file order.

    Uses a compiled regex (C speed) rather than a per-byte Python loop. Pass
    ``limit`` to stop scanning once enough strings are found -- callers that only
    need a sample (e.g. the first 40) no longer pay for a full pass over the file.
    """
    output: list[str] = []
    for match in _pattern(min_length).finditer(data):
        output.append(match.group().decode('ascii'))
        if limit is not None and len(output) >= limit:
            break
    return output
