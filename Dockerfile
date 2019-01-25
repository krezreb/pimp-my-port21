FROM alpine

RUN apk add --no-cache bash certbot python proftpd

RUN mkdir -p /sslcert

RUN rm /etc/proftpd/conf.d/* 
RUN rm /etc/proftpd/proftpd.conf

ADD proftpd.conf /etc/proftpd/

ADD setup.py /usr/local/bin/setup
ADD run.sh /
RUN chmod +x /usr/local/bin/setup /run.sh

ADD conf.example.json /etc/301hub/

ENV CERTBOT_PORT=80
ENV SETUP_REFRESH_FREQUENCY=86400

CMD ["/run.sh"]