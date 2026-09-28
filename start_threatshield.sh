#!/bin/bash

cd "$(dirname "$0")"

source .venv/bin/activate

echo "======================================"
echo " CYBERIAN THREATSHIELD"
echo " SOC PLATFORM"
echo "======================================"

echo
echo "Dashboard:"
echo "http://127.0.0.1:8001/"

echo
echo "API Docs:"
echo "http://127.0.0.1:8001/docs"

echo

uvicorn application.backend.main:app \
    --host 0.0.0.0 \
    --port 8001 \
    --reload
