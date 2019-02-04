#!/usr/bin/env bash

trap "exit" INT TERM
trap "kill -9 0" EXIT

mkdir -p /mnt/ftpdata /mnt/ftpparameter_store

set -ue

s3fs $APP_DATA_BUCKET:/ftpdata/${AWS_ENV} /mnt/ftpdata -o iam_role,allow_other,uid=1000,gid=1000
s3fs $PARAMETER_STORE_BUCKET:/ftpdata/${AWS_ENV} /mnt/ftpparameter_store -o iam_role,allow_other,uid=1000,gid=1000

export USER_CONF_PATH=/users

setup 