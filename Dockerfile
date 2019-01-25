FROM python:2.7-slim

EXPOSE 20 21 22 80

RUN apt update \
    && apt install --no-install-recommends -y bash certbot openssl proftpd \
    && apt clean

ADD requirements.txt /usr/local/bin/

RUN pip install -r /usr/local/bin/requirements.txt

RUN mkdir -p /sslcert /etc/proftpd/ /var/proftpd/home

ADD proftpd.conf /etc/proftpd/

ADD setup.py /usr/local/bin/setup
ADD gen_self_signed_cert.sh /usr/local/bin/gen_self_signed_cert
ADD run.sh /
RUN chmod +x /usr/local/bin/setup /run.sh /usr/local/bin/gen_self_signed_cert

ADD conf.json /etc/proftpd/

ENV CERTBOT_PORT=80
ENV SETUP_REFRESH_FREQUENCY=86400

CMD ["/run.sh"]