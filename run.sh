#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -u

# regularly rerun setup
(while true ; do sleep $SETUP_REFRESH_FREQUENCY ; setup ; done) &

set -e

setup 

touch /etc/proftpd/ftpusers
chmod 600 /etc/proftpd/ftpusers

chmod -R 775 /var/proftpd/home

echo Starting Proftpd
/usr/sbin/proftpd -n -c /etc/proftpd/proftpd.conf