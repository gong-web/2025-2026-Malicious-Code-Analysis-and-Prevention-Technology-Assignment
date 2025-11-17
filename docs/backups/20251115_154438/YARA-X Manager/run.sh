#!/usr/bin/env bash
set -e

unzip my_rules.zip

# 0. install redis if missing
if ! command -v redis-server >/dev/null 2>&1; then
    echo "installing redis"
    sudo apt-get update -y
    sudo apt-get install -y redis-server
fi

# 1. install yara-x if missing
if ! command -v yara-x >/dev/null 2>&1; then
    wget -O yara-x.tar.gz https://github.com/VirusTotal/yara-x/releases/download/v1.9.0/yara-x-v1.9.0-x86_64-unknown-linux-gnu.gz
    gunzip -f yara-x.tar.gz
    tar -xf yara-x.tar
    chmod +x yr
    sudo ln -s "$(pwd)/yr" /usr/local/bin/yara-x
    rm -f yara-x.tar
fi

# 2. start redis
if ! pgrep redis-server >/dev/null; then
    redis-server --daemonize yes
fi

# 3. venv setup
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt

# 4. start celery
celery -A app.celery_app.cel worker --loglevel=info &
CELERY_PID=$!

# 5. start API
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

kill $CELERY_PID || true

rm -f data.sqlite

rm -rf my_rules

rm -rf data/rules/*