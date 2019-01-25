#!/usr/bin/env python

import json, os
from subprocess import Popen, PIPE
from OpenSSL import crypto
import datetime
import shutil
from urlparse import urlparse
from urllib2 import urlopen
import socket
import crypt

CERTBOT_PORT=os.environ.get('CERTBOT_PORT', '80')
CONF_PATH = os.environ.get('CONF_PATH', '/etc/proftpd/conf.json')
PROFTPD_DEFAULTROOT = os.environ.get('PROFTPD_DEFAULTROOT', '/var/proftpd/home')
PROFTPD_USERS_FILE = os.environ.get('PROFTPD_USERS_FILE', '/etc/proftpd/ftpusers')
PROFTPD_CONF_PATH = os.environ.get('PROFTPD_CONF_PATH', '/etc/proftpd/proftpd.conf.d/')
CERT_PATH = os.environ.get('CERT_PATH', '/etc/letsencrypt/live')
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 22))
CHECK_IP_URL=os.environ.get('CHECK_IP_URL', 'http://ip.42.pl/raw')
MY_HOSTNAME=os.environ.get('MY_HOSTNAME', None)
MY_IP=None


def run(cmd, splitlines=False):
    # you had better escape cmd cause it's goin to the shell as is
    proc = Popen([cmd], stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    out, err = proc.communicate()
    if splitlines:
        out_split = []
        for line in out.split("\n"):
            line = line.strip()
            if line != '':
                out_split.append(line)
        out = out_split

    exitcode = int(proc.returncode)

    return (out, err, exitcode)


def log(s):
    print("SETUP: {}".format(s))

def get_my_ip():
    global MY_IP
    
    if MY_IP == None:
        MY_IP = urlopen(CHECK_IP_URL).read()

        if MY_HOSTNAME != None:
            ip = socket.gethostbyname(MY_HOSTNAME)
            if ip != MY_IP:
                log("CONFIG ERROR: env var MY_HOSTNAME={} which resolves to ip {}. But according to {} my ip is {}".format(MY_HOSTNAME, ip, CHECK_IP_URL, MY_IP))
                exit(-100)
                
        log("My ip appears to be {}".format(MY_IP))

    return MY_IP


def points_to_me(s):
    get_my_ip()
    
    url = 'http://{}'.format(s)
    # from urlparse import urlparse  # Python 2
    parsed_uri = urlparse(url)
    domain = parsed_uri.netloc.split(':')[0]
    success = False
    ip = None
    try:
        ip = socket.gethostbyname(domain)

        if ip == MY_IP:
            success = True
    except Exception as e:
        log(e)
        
    return (success, domain, ip, MY_IP)

def main():
    log("Start")
    try:
        with open(CONF_PATH, 'r') as f:
            conf = json.load(f)
    except IOError:
        log("ERROR: No config file found at {}, quitting".format(CONF_PATH))
        exit(-1)
    
    proftpd_reload = False
    
    with open(PROFTPD_USERS_FILE, "w") as fh:
    
        for u in conf["users"]:
            
            # http://www.proftpd.org/docs/howto/AuthFiles.html
            # username:password:uid:gid:gecos:homedir:shell
            
            hash =  crypt.crypt(u['password'], "$1$")
            home = PROFTPD_DEFAULTROOT+'/'+u['user']
            fh.write("{}:{}:100:100:ftp user:{}:/bin/false\n".format(u['user'],hash, home))
            if not os.path.isdir(home):
                os.mkdir(home)
            
            continue
            cert_file=CERT_PATH+'/'+d['from']+'/cert.pem'
            (points_to_me_from, domain_from, ip_from, my_ip) = points_to_me(d['from'])
            (points_to_me_to, domain_to, ip_to, my_ip) = points_to_me(d['to'])
    
            fail = False
            if ip_from == None:
                if MY_HOSTNAME != None:
                    log("DNS ERROR: No DNS entry found for {}.  Create an A record pointing to my ip ({}), or a CNAME pointing to {} then rerun setup".format(domain_from, my_ip, MY_HOSTNAME))
                else:
                    log("DNS ERROR: No DNS entry found for {}.  Create an A record pointing to my ip ({}) then rerun setup".format(domain_from, my_ip))
                    
                fail = True
    
            elif not points_to_me_from:
                log("DNS ERROR: Cannot request or renew certificate for {}.  It points to {} rather than my ip, which is {}.  Update DNS records and rerun setup".format(domain_from, ip_from, my_ip))
                fail = True
    
            elif points_to_me_to:
                log("CONFIG ERROR: Cannot forward {} to {} (ip {}).  This is the same as my ip, which would make an infinite loop.".format(domain_from, domain_to, ip_to))
                fail = True
                
            if fail:
                if os.path.isfile(cert_file):
                    os.remove(conf_file)
                    proftpd_reload = True
                continue
            
            if ip_to == None:
                log("DNS WARNING: No DNS entry found for {}.  Forwarding from {} won't work until a DNS record is created.".format(domain_to, domain_from))
                
            if os.path.isfile(cert_file):
                # cert already exists
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
                exp = datetime.datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
                
                expires_in = exp - datetime.datetime.utcnow()
                
                if expires_in.days <= 0:
                    log("Found cert {} EXPIRED".format(d['from']))
                else:
                    log("Found cert {}, expires in {} days".format(d['from'], expires_in.days))
        
                if expires_in.days < CERT_EXPIRE_CUTOFF_DAYS:
                    log("Trying to renew cert {}".format(d['from']))
                    cmd = "certbot certonly --verbose --noninteractive --preferred-challenges http --standalone --http-01-port 8086 --agree-tos -d {}".format(d['from'])
                    (out, err, exitcode) = run(cmd)
                    
                    if exitcode == 0:
                        log("RENEW SUCCESS: Certificate {} successfully renewed".format(d['from']))
                        proftpd_reload = True
    
                    else:
                        log("RENEW FAIL: ERROR renewing certificate {}".format(d['from']))
                        log(out)
                        log(err)
                        
            try:
                email = d['email']
            except KeyError:
                email = conf['email']
                
            cmd = 'certbot certonly --verbose --noninteractive --quiet --standalone  --http-01-port {} --agree-tos --email="{}" '.format(CERTBOT_PORT, email)
            cmd += ' -d "{}"'.format(d['from'])
    
            from2 = d['from'].replace('/', '_')
            proftpd_conf = template(http_port=80, https_port=443, server_name=d['from'], forward_to=d['to'])
            
            conf_file = '{}{}'.format(PROFTPD_CONF_PATH, from2)
            
            if not os.path.isdir(PROFTPD_CONF_PATH):
                os.makedirs(PROFTPD_CONF_PATH)
            
            # always remove conf file
            if os.path.isfile(conf_file):
                os.remove(conf_file)
            
            if not os.path.isfile(cert_file):
                (out, err, exitcode) = run(cmd)
                
                if exitcode != 0:
                    log("Requesting cert for {}: FAILED".format(d['from']))
                    log(cmd)
                    log(err)
                else:
                    log("Requesting cert for {}: SUCCESS".format(d['from']))
                    # write conf
                    with open(conf_file, 'w') as f:
                        f.write(proftpd_conf)
                        log("Configured forwarding {} => {}".format(d['from'], d['to']))
                        proftpd_reload = True
            else:
                # write conf
                with open(conf_file, 'w') as f:
                    f.write(proftpd_conf)
                    log("Configured forwarding {} => {}".format(d['from'], d['to']))
                    proftpd_reload = True
    
    if proftpd_reload:
        log("Reloading proftpd")
        reload()
            
    log("Done")
    
    
def reload():
    (out, err, exitcode) = run("kill -HUP $(pgrep proftpd)")


main()