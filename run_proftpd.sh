#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

mkdir -p /var/proftpd/home
mkdir -p /var/proftpd/authorized_keys

set -ue

touch /var/proftpd/ftpusers
touch /var/proftpd/sftpusers
chmod 600 /var/proftpd/ftpusers
chmod 600 /var/proftpd/sftpusers
chmod -R 700 /var/proftpd/home

# regularly refresh proftpd to grab any new ssl cert changes
(while true ; do sleep $SETUP_REFRESH_FREQUENCY ; kill -HUP $(pgrep proftpd) ; done) &

/usr/local/sbin/proftpd -n -c ${PROFTPD_CONF_FILE}