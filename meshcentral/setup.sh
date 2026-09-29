#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root."
  exit 1
fi

read -r -p "MeshCentral hostname (example: remote.example.com): " HOST
read -r -p "Let's Encrypt email: " EMAIL

if [ -z "$HOST" ] || [ -z "$EMAIL" ]; then
  echo "Hostname and email are required."
  exit 1
fi

mkdir -p data files backups
cp config.template.json data/config.json

python3 - "$HOST" "$EMAIL" <<'PY'
import pathlib, sys
p = pathlib.Path("data/config.json")
s = p.read_text()
s = s.replace("MESH_HOSTNAME", sys.argv[1]).replace("LETSENCRYPT_EMAIL", sys.argv[2])
p.write_text(s)
PY

chmod 700 data files backups
docker compose up -d

echo
echo "MeshCentral is starting."
echo "Open: https://$HOST"
echo "Create the FIRST admin account immediately. New account creation is disabled after that first account."
