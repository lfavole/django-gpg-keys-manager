#!/usr/bin/env bash
set -euo pipefail

# Compile translation messages (if any .po files are present)
dnf install -y gettext
python3 -m uv run manage.py compilemessages --ignore .venv || true

# Collect static files
python3 -m uv run manage.py collectstatic --noinput

# Install an additional dependency so that pgpy works
dnf install -y libffi-devel

# Remove the created virtual environment
rm -rf .venv || true
