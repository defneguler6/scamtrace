#!/bin/bash
# Start the API on the data the demo created. Run demo/run_demo.py first.
source .venv/bin/activate
export SCAMTRACE_DB=demo/output/demo.db
export SCAMTRACE_EVIDENCE=demo/output/screens
export SCAMTRACE_HASH_KEY=demo-hash-key
echo "Open http://127.0.0.1:8000/docs  (API key: demo-key)"
uvicorn scamtrace.api:app --reload
