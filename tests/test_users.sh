#!/bin/sh

export tmpdir=$(mktemp -d)

trap "rm -rf $tmpdir" EXIT

export LIMITS_CONF_FILE=/tmp/limits.conf

export SETUP_DOCKER_IMAGE=proftpd-admin

export USER_CONF_PATH=/users/      
export ACCOUNTS_REPORT_FILE=/$tmpdir/accounts.json

touch $ACCOUNTS_REPORT_FILE
export WDIR=$(pwd)

# runnit!!
docker run -it \
-e USER_CONF_PATH \
-e LIMITS_CONF_FILE \
-e ACCOUNTS_REPORT_FILE \
-v "${WDIR}/tests/testusers:/users/"  \
-v $ACCOUNTS_REPORT_FILE:$ACCOUNTS_REPORT_FILE \
$SETUP_DOCKER_IMAGE setup


cat $ACCOUNTS_REPORT_FILE
          
