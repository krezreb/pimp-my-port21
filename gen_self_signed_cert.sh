#!/usr/bin/env bash


cd /var/ssl/

openssl req -nodes -new -x509 -keyout key.pem -out cert.pem
