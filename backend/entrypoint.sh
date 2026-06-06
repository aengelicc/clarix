#!/bin/sh
# Container entrypoint: dispatch between the Clarix web API and the CLI.
#
# Usage:
#   docker run clarix                   # default: web API on port 8000
#   docker run clarix serve            # explicit: web API on port 8000
#   docker run clarix scan /src ...    # CLI: scan a path
#   docker run clarix rules [--scanner X]
#   docker run clarix version

set -e

CMD=${1:-serve}

if [ "$CMD" = "serve" ]; then
    # Default API mode. Drop the 'serve' arg if it was explicit; otherwise
    # just append the default uvicorn invocation.
    if [ "$#" -gt 0 ]; then
        shift
    fi
    exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" "$@"
fi

# Anything else (scan, rules, version, ...) goes to the CLI.
exec clarix "$@"
