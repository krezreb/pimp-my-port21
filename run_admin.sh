#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -ue

setup 

# regularly rerun setup
(while true ; do sleep $SETUP_REFRESH_FREQUENCY ; setup ; done) 

