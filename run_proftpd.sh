#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

set -u

mkdir -p ${FTP_HOME_PATH}

set -e

touch ${LIMITS_CONF_FILE}
touch ${FTP_USERS_FILE}
touch ${SFTP_USERS_FILE}
touch ${LIMITS_CONF_FILE}

chmod 600 ${FTP_USERS_FILE}
chmod 600 ${SFTP_USERS_FILE}
chmod -R 700 ${FTP_HOME_PATH}

# regularly refresh proftpd to grab any new ssl cert changes
(while true ; do sleep $PROFTPD_REFRESH_FREQUENCY ; kill -HUP $(pgrep proftpd) ; done) &

proftpd -n -c ${PROFTPD_CONF_FILE}