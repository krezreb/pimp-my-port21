#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -u

# regularly rerun setup
(while true ; do sleep $SETUP_REFRESH_FREQUENCY ; setup ; done) &

set -e

setup &

echo Starting Nginx 
nginx -g "daemon off;"