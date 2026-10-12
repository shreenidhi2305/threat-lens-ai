# Deployment

ThreatLens ships as two Docker images behind one port:

```
browser -> web (nginx: static UI + reverse proxy)  -> api (FastAPI, ML model, YARA)
              :8080 (the only published port)           internal :8000
```

The browser only talks to `web`; nginx serves the built UI and proxies `/api` to the backend,
so there is no CORS to configure and the API is never exposed directly.

## What you can do for free, with no cloud account

| Goal | How |
|---|---|
| Run the full stack anywhere Docker runs (laptop, VM, spare PC) | `docker compose up --build -d` |
| A free public link (needs a free account) | Render web service, see below |
| Share it over a temporary public https URL | `docker compose --profile public up -d` (Cloudflare quick tunnel, no account) |
| Build, test and publish the images automatically | `.github/workflows/ci.yml` (GitHub Actions + GitHub Container Registry, free for repositories) |

Hosted platforms (AWS, Azure, Render, Fly, ...) all need an account. When you have one, the same
two images deploy unchanged; see [Moving to a cloud host](#moving-to-a-cloud-host).

## A free public link (Render)

For a link you can send to someone, use a free **Render** web service. It runs the app as one
container (the API serves the built UI itself), and the app uses about 250 MB of memory, inside the
free plan's 512 MB. You need a free Render account and the project on a GitHub repository Render can
read. Free web services should not need a credit card; if Render asks for one, stop and tell your team.

1. **Put the code where Render can read it.** Either use the team repository, or create your own empty
   GitHub repository and push this project to it (`git remote add mine <url>`,
   `git push mine main`). `render.yaml` and `deploy/allinone/Dockerfile` must be on the branch you deploy.
2. Sign up at https://render.com (the "Sign in with GitHub" button is the easiest) and let it access
   that repository.
3. **New, Blueprint**, pick the repository and branch, and click **Apply**. Render reads `render.yaml`:
   it builds `deploy/allinone/Dockerfile`, starts the service on the free plan, and **generates the two
   secrets for you**. The first build takes about 10 minutes.
4. When it shows **Live**, the link is at the top of the service page
   (`https://threatlens-ai.onrender.com`, or with a short suffix if the name was taken).
5. **The sign-in password:** service, **Environment**, `DEV_LOGIN_PASSWORD`, then **reveal**. It is a long
   random value. If you want something easier to share, edit it there to your own 12+ character
   password (Render redeploys).
6. Send your mentor the link, the password and the accounts: `analyst@local`, `soc@local`,
   `admin@local`, `researcher@local`.

Without the Blueprint (a plain **New, Web Service** on a public repository): choose **Docker**, set the
Dockerfile path to `./deploy/allinone/Dockerfile`, the instance type to **Free**, the health check path to
`/health`, and add `JWT_SECRET_KEY` and `DEV_LOGIN_PASSWORD` yourself as environment variables.

What to know:
- Free services **sleep after 15 minutes idle** and take about a minute to wake on the next visit, so open
  the link yourself a couple of minutes before a review.
- Data is held in memory and resets on every restart or wake; the dashboards are re-filled with the
  synthetic demo samples each time (`SEED_DEMO_DATA`), so reviewers never land on empty pages.
- The free plan has little CPU, so large files scan slowly. The demo files are small.
- Anyone with the link **and** the password can sign in. Do not put real data in it.
- CI builds this exact image from the repository root and smoke-tests it on every push (`allinone` job).

**If you would rather not create any account:** run it on your own PC and use a free Cloudflare quick tunnel
(`docker compose --profile public up -d`, see above). It only works while your PC is on.

**Hugging Face Spaces** also works with the same image (`deploy/huggingface/deploy.py`), but Hugging
Face now requires a paid PRO subscription for Docker Spaces, so it is not a free option.

## Run it (demo mode, no accounts)

Needs Docker (Docker Desktop on Windows/macOS, Docker Engine on Linux) and Python 3 for one helper script.

```bash
python deploy/make_env.py --demo      # writes .env with fresh secrets and prints the sign-in password
docker compose up --build -d
```

Open **http://localhost:8080** and sign in as `analyst@local`, `soc@local`, `admin@local` or
`researcher@local` with the printed password. To fill every dashboard with realistic data:

```bash
python demo/m4_end_to_end_demo.py --api http://localhost:8080/api/v1 --password <the printed password>
```

Demo mode has no identity provider: everyone signs in with one shared password. It is for
demonstrations, not real data. (`make_env.py` never overwrites an existing `.env`; use `--force`.)

## Share a public URL (free, temporary)

```bash
docker compose --profile public up -d
docker compose logs tunnel | grep trycloudflare.com     # the https://....trycloudflare.com URL
```

Anyone with the URL **and** the shared password can sign in. The URL changes every time the tunnel
restarts and has no uptime guarantee, which is fine for a demo or a reviewer. Stop sharing with
`docker compose stop tunnel`.

## A real deployment (needs accounts)

1. **Supabase** (free tier): create a project, run `supabase/migrations/001`-`006` and
   `supabase/seed/001_seed_roles.sql` (see `supabase/README.md`), and make your first user an
   administrator.
2. `python deploy/make_env.py` (without `--demo`), then fill in `SUPABASE_URL` and
   `SUPABASE_SERVICE_KEY`. Optional: `VIRUSTOTAL_API_KEY`, `SMTP_*`, `SIEM_WEBHOOK_*`
   (all listed in `.env.example`; the SIEM and email links can be tested from the Admin Console).
3. `docker compose up --build -d`.
4. Put **TLS** in front (a managed load balancer, Caddy, or Cloudflare). The bundled nginx speaks
   plain HTTP on the published port.

With Supabase configured, sign-in uses real accounts, and detections, alerts, incidents,
notifications, reports, the audit log and uploaded samples are stored in your project.

## Safe by default

The API image starts in `APP_ENV=production` and **refuses to boot** with the default JWT secret, with
no identity provider, or with an open "any password" dev login. The message says what to fix:

```
Refusing to start in production with unsafe configuration: JWT_SECRET_KEY is the default ...
```

`make_env.py` generates a strong secret for you. Further guard rails: rate limiting on every request
and a stricter limit on sign-ins, security headers and a content-security policy from nginx, a
non-root container, and an audit log of administrator actions.

## Operating it

| Task | Command |
|---|---|
| Status and health | `docker compose ps` (both services report healthy) |
| Logs | `docker compose logs -f api` |
| Update | `git pull && docker compose up --build -d` |
| Stop | `docker compose down` (data survives) |
| Wipe all local data | `docker compose down -v` |

- **Data:** the `threatlens-data` volume keeps uploaded samples and settings changed in the Admin
  Console. Without Supabase, detections, alerts and reports live in memory and reset when the API
  restarts; with Supabase they persist.
- **One API process on purpose:** alerts, notifications and rate limits are held in-process. To run
  several replicas, move those to shared storage (Redis) first; see `docs/ARCHITECTURE.md`.
- **Port:** set `WEB_PORT` in `.env` to publish something other than 8080.
- **Models:** after retraining, copy the new artifacts into `backend/app/ml/models/artifacts`,
  rebuild, or hot-reload them from the Admin Console's ML models tab.

## Moving to a cloud host

CI publishes both images to the GitHub Container Registry on every push to `main`:

```
ghcr.io/<owner>/<repo>/api:latest      port 8000, set the variables from .env.example
ghcr.io/<owner>/<repo>/web:latest      port 80, expects the API reachable as host "api:8000"
```

Any container platform can run them: Azure Container Apps, AWS App Runner or ECS, Google Cloud Run,
Render, Fly.io. Run `api` with a single instance, give it the environment from `.env.example` and a
volume at `/app/var`, and run `web` in front of it. If the platform names the API service
differently, change `api:8000` in `frontend/nginx.conf` (two places) or put your own proxy in front.

## How this is verified

`.github/workflows/ci.yml` runs on every push and pull request: backend tests, frontend build, then
it builds both images, starts the stack with `docker compose`, checks the nginx security headers and
that the ML model loads **inside the container**, and runs the end-to-end demo against it. A broken
Dockerfile, nginx config or missing system library fails the build.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `api` exits at start with "Refusing to start..." | Unsafe production config. Read the message; `python deploy/make_env.py --demo --force` produces a valid one |
| Every verdict says "rules only" / ML unavailable | The model did not load. Check `GET /api/v1/malware/model`; the image installs `libgomp1` for LightGBM, so this means artifacts are missing |
| Login says "Authentication is not configured" (503) | Production with no Supabase and no `ALLOW_DEV_LOGIN`; use demo mode or configure Supabase |
| `429 Too Many Requests` | The rate limiter; wait a minute or raise the limits in the Admin Console |
| Browser shows CORS errors | You are bypassing nginx. Use the web port, or add your frontend origin to `CORS_ALLOW_ORIGINS` |
| Building the frontend outside Docker on Windows with Git Bash turns `/api/v1` into `C:/Program Files/Git/api/v1` | Git Bash rewrites path-like variables. Use PowerShell, or prefix `MSYS_NO_PATHCONV=1` |
