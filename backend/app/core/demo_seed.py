"""Fill a fresh public demo with realistic data so reviewers don't land on empty dashboards.

Scans the bundled synthetic samples (none is live malware) through the real pipeline, then
acknowledges one alert and opens an incident so every screen has something to show. Runs once at
start-up in a background thread when ``SEED_DEMO_DATA`` is on. Data lives in memory, so it is
recreated on every restart.
"""

from __future__ import annotations

import logging
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)

_SAMPLES = [
    'clean_notes.txt',
    'injector_strings.txt',
    'packed_blob.bin',
    'invoice_2026.pdf.exe',
    'upload.php',
    'invoice_macro.doc.txt',
    'README_TO_DECRYPT.txt',
    'trojan_downloader.bin',
]


def seed_demo_data(pipeline=None, alerts=None, storage=None) -> int:
    """Scan the demo samples. Returns how many were scanned. Never raises."""
    if not settings.DEMO_SAMPLES_DIR:
        return 0
    folder = Path(settings.DEMO_SAMPLES_DIR)
    if not folder.is_dir():
        logger.warning('DEMO_SAMPLES_DIR=%s not found; skipping demo data', folder)
        return 0

    if pipeline is None or alerts is None or storage is None:
        from app.modules.alerts.service import alerts_service
        from app.modules.file_analysis import storage as storage_module
        from app.modules.pipeline.service import pipeline_service

        pipeline = pipeline or pipeline_service
        alerts = alerts or alerts_service
        storage = storage or storage_module

    scanned = 0
    for name in _SAMPLES:
        path = folder / name
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
            pipeline.scan(storage.object_path_for(data, name), data, actor='demo-seed')
            scanned += 1
        except Exception:  # noqa: BLE001 - seeding is a nicety, never a startup blocker
            logger.exception('Demo seed: could not scan %s', name)

    try:
        open_alerts = alerts.list_alerts(status='open')
        if open_alerts:
            alerts.set_status(open_alerts[-1].id, 'acknowledged')
        if len(open_alerts) >= 3:
            alerts.create_incident([a.id for a in open_alerts[:2]], 'Demo campaign: downloader and macro dropper')
    except Exception:  # noqa: BLE001
        logger.exception('Demo seed: could not set up alert and incident examples')

    logger.info('Demo seed: scanned %d sample(s)', scanned)
    return scanned
