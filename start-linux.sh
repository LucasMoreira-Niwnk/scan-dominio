#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
PORT="${PORT:-4173}" NODE_ENV="${NODE_ENV:-production}" node server.js
