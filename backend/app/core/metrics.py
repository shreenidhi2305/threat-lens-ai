"""In-process request metrics for the administrator's platform monitor."""

from __future__ import annotations

import threading
import time
from collections import deque


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started_at = time.time()
        self.total = 0
        self.rate_limited = 0
        self.slow = 0
        self.by_class: dict[str, int] = {'2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0}
        self._latencies: deque[float] = deque(maxlen=500)

    def record(self, status_code: int, elapsed_seconds: float, slow: bool = False) -> None:
        with self._lock:
            self.total += 1
            key = f'{status_code // 100}xx'
            self.by_class[key] = self.by_class.get(key, 0) + 1
            if status_code == 429:
                self.rate_limited += 1
            if slow:
                self.slow += 1
            self._latencies.append(elapsed_seconds)

    def snapshot(self) -> dict:
        with self._lock:
            lat = sorted(self._latencies)
            avg = sum(lat) / len(lat) if lat else 0.0
            p95 = lat[min(len(lat) - 1, int(len(lat) * 0.95))] if lat else 0.0
            return {
                'uptime_seconds': int(time.time() - self.started_at),
                'total_requests': self.total,
                'by_status_class': dict(self.by_class),
                'rate_limited': self.rate_limited,
                'slow_requests': self.slow,
                'avg_latency_ms': round(avg * 1000, 1),
                'p95_latency_ms': round(p95 * 1000, 1),
                'sampled_requests': len(lat),
            }


metrics = Metrics()
