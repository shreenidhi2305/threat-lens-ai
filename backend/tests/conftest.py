"""Test configuration.

Runs before any test module imports the app, so these environment variables are read
by ``app.core.config.Settings``. The suite fires far more requests than a real user
would, so the API gateway rate limiter is off by default (tests that exercise it turn
it on explicitly), and administrator settings are saved to a throwaway file instead of
``backend/var/``.
"""

import os
import tempfile

os.environ.setdefault('RATE_LIMIT_ENABLED', 'false')
os.environ.setdefault(
    'PLATFORM_SETTINGS_FILE',
    os.path.join(tempfile.mkdtemp(prefix='threatlens-tests-'), 'platform_settings.json'),
)
# Never let a developer's local .env (Supabase keys, SMTP, SIEM) leak into the test run.
for _name in (
    'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'SMTP_HOST', 'ALERT_EMAIL_TO',
    'SIEM_WEBHOOK_URL', 'VIRUSTOTAL_API_KEY',
):
    os.environ[_name] = ''
os.environ['APP_ENV'] = 'development'
