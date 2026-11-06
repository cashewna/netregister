#!/bin/sh
# Host-side wrapper for the isolated compose proof. Tears the lab down first so
# the database starts empty, then runs both scans and the assertions inside the
# scanner container. The lab is torn down even when the proof fails.
set -u
cd "$(dirname "$0")/.."

docker compose down --volumes --remove-orphans || true
status=0
docker compose up --build --abort-on-container-exit --exit-code-from scanner || status=$?
docker compose down --volumes --remove-orphans || true
exit "$status"
