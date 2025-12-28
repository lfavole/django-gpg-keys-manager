# django-gpg-keys-manager

Reusable Django app to manage GPG public keys (export, verification, temporary keys fetched from keyservers).

## Quickstart

1. Create and activate a Python virtualenv

```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install dependencies

```bash
pip install -r requirements.txt || pip install Django pgpy django-allauth
```

3. Run the example project (from repository root)

The repository includes helper tooling that integrates with the `uv` runner (used in this workspace).

Using `uv` (recommended in this workspace):

```bash
uv run manage.py migrate
uv run manage.py runserver
```

Or directly with Python:

```bash
python manage.py migrate
python manage.py runserver
```

The example project mounts the app at `/gpg/`.

## Notes
- The repository contains two app locations: the original `gpg/` and the new reusable package `gpg_keys/`.
- The module `gpg_keys.utils.get_request()` finds the active Django `HttpRequest` by walking stack frames; it's used where a global `request` variable used to be imported from `project.middleware`.

## Vercel deployment

This repository includes helper files for deploying to Vercel. Vercel will install dependencies from `requirements.txt` automatically. The build step compiles translations and collects static files.

Files added for Vercel:
- `requirements.txt` — Python dependencies
- `build.sh` — run `python manage.py compilemessages` and `python manage.py collectstatic --noinput`
- `vercel.json` — Vercel configuration (adjust if needed for your setup)

On Vercel the build will run `build.sh` and the Python server runtime will serve the Django app. You may need to set environment variables (e.g., `DJANGO_SECRET_KEY`, `DATABASE_URL`) in the Vercel project settings.
