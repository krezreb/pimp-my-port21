#!/usr/bin/env python

import os, json
import yaml_ordered as yo
from subprocess import Popen, PIPE
from OpenSSL import crypto
import datetime
import shutil
from urlparse import urlparse
from urllib2 import urlopen
import socket
import crypt
import string, random

CERTBOT_PORT=os.environ.get('CERTBOT_PORT', '80')
CONF_PATH = os.environ.get('CONF_PATH', '/etc/proftpd/')
FTP_HOME_PATH = os.environ.get('FTP_HOME_PATH', '/var/proftpd/home')
FTP_USERS_FILE = os.environ.get('FTP_USERS_FILE', '/var/proftpd/ftpusers')
SFTP_USERS_FILE = os.environ.get('SFTP_USERS_FILE', '/var/proftpd/sftpusers')
USER_KEYS_PATH = os.environ.get('USER_KEYS_PATH', '/var/proftpd/authorized_keys')
PASSWORD_STORE_PATH = os.environ.get('PASSWORD_STORE_PATH', '/var/proftpd/passwords')

PASSWORD_MIN_LENGTH=int(os.environ.get('PASSWORD_MIN_LENGTH', 10))
SSL_CERT_EMAIL=os.environ.get('SSL_CERT_EMAIL', "you@example.com")
SSL_CERT_FQDN=os.environ.get('SSL_CERT_FQDN', None)
CERT_PATH = os.environ.get('CERT_PATH', '/etc/letsencrypt/live')
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 31))
CHECK_IP_URL=os.environ.get('CHECK_IP_URL', 'http://ip.42.pl/raw')
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

def genpw(length=32):
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(length))

def get_password(username):
    
    if not os.path.isdir(PASSWORD_STORE_PATH):
        os.makedirs(PASSWORD_STORE_PATH)
        
    password_file = "{}/{}".format(PASSWORD_STORE_PATH, username)
    
    if not os.path.isfile(password_file):
        password = genpw()
        
        with open(password_file, 'w') as fh:
            json.dump(password, fh)
            
    else:
        with open(password_file, 'r') as fh:
            password = json.load(fh)
        
    return password
    

def make_accounts():
    log("Start")
    
    try:
        conf = yo.load(CONF_PATH+'/conf.yml')
    except IOError:
        log("ERROR: No config file found at {}, quitting".format(CONF_PATH))
        exit(-1)
    
    proftpd_reload = False
    
    ftpfh  = open(FTP_USERS_FILE, "w")
    sftpfh = open(SFTP_USERS_FILE, "w")
    
    #with open(PROFTPD_USERS_FILE, "w") as fh:
    
    for raw_username, u in conf["users"].items():
        
        try:
            prefix = conf['user_prefix']
            if len(prefix) > 0:
                username = "{}_{}".format(prefix, raw_username)
        except KeyError:
            username = raw_username
        
        # http://www.proftpd.org/docs/howto/AuthFiles.html
        # username:password:uid:gid:gecos:homedir:shell
        
        password = get_password(username)
        
        if len(password) < PASSWORD_MIN_LENGTH:
            log("Password provided for user {} is less than the minimum {} characters, skipping".format(username, PASSWORD_MIN_LENGTH))
            continue
        
        
        hash =  crypt.crypt(password, "$1${}".format(genpw(16)))
        home = FTP_HOME_PATH+'/'+username
        # here we put 0 for uid and gid (root) because we don't care about perms here =) 
        user_line = "{}:{}:0:0::{}:/bin/false\n".format(username,hash, home)
        
        protocols = []
        if u != None:
            try:
                protocols = u['protocols']
            except KeyError:
                pass
            
        if u != None:
            try:
                keys = u['authorized_keys']
                keyfile = '{}/{}'.format(USER_KEYS_PATH, username)
    
                if not os.path.isdir(USER_KEYS_PATH):
                    os.makedirs(USER_KEYS_PATH)
                    
                with open(keyfile, "w") as fac:
                    for k in keys:
                        fac.write("---- BEGIN SSH2 PUBLIC KEY ----\n")
                        rawkey = k.split(" ")[1]
                        
                        line = ""
                        for ch in rawkey:
                            line+=ch
                            if len(line) == 64:
                                fac.write("{}\n".format(line))
                                line=""
                        fac.write("{}\n".format(line))
                        fac.write("---- END SSH2 PUBLIC KEY ----\n")
                       
                protocols.append('sftp')
                             
            except KeyError:
                protocols.append('ftp') # no rsa key set so ftp
                pass
        else:
            protocols.append('ftp') # no rsa key set so ftp
            
        
        if 'sftp' in protocols:
            log("Authing user {} for sftp using their key(s)".format(username))
            sftpfh.write(user_line)
            
        if 'ftp' in protocols:
            log("Authing user {} for ftp using their password".format(username))
            ftpfh.write(user_line)
            
                    
        if not os.path.isdir(home):
            os.makedirs(home)
        
        limits_conf_file = '{}/conf.d/{}.conf'.format(CONF_PATH, username)
        #limits_conf_file = '{}/.limits_conf_file'.format(FTP_HOME_PATH)
        
        if os.path.isfile(limits_conf_file):
            os.remove(limits_conf_file)
            
        if u != None:
            try:
                ips = u['authorized_ips']
                with open(limits_conf_file, "w") as fac:
                    fac.write("<IfUser {}>\n<Limit LOGIN>\n".format(username))
                    for ip in ips:
                        fac.write("Allow from {}\n".format(ip))
                    fac.write("DenyAll\n</Limit>\n</IfUser>\n")
                
            except KeyError:
                pass
        
    ftpfh.close()
    sftpfh.close()
    
    if proftpd_reload:
        pass
            

    log("Done")
    

def get_ssl_cert():
    
    if SSL_CERT_FQDN != None:
    
        cert_file=CERT_PATH+'/'+SSL_CERT_FQDN+'/cert.pem'
        
        (success, domain, ip, MY_IP) = points_to_me(SSL_CERT_FQDN)
    
        if not success:
            if ip != MY_IP:
                log("DNS ERROR: Cannot request or renew certificate for {}.  It points to {} rather than my ip, which is {}.  Update DNS records and rerun setup".format(domain_from, ip_from, my_ip))
            elif SSL_CERT_FQDN != None:
                log("DNS ERROR: No DNS entry found for {}.  Create an A record pointing to my ip ({}), or a CNAME pointing to {} then rerun setup"
                    .format(SSL_CERT_FQDN, MY_IP, SSL_CERT_FQDN))
            else:
                log("DNS ERROR: SSL_CERT_FQDN env var not set.")
                
            return
    
        if os.path.isfile(cert_file):
            # cert already exists
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
            exp = datetime.datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
            
            expires_in = exp - datetime.datetime.utcnow()
            
            if expires_in.days <= 0:
                log("Found cert {} EXPIRED".format(SSL_CERT_FQDN))
            else:
                log("Found cert {}, expires in {} days".format(SSL_CERT_FQDN, expires_in.days))
    
            if expires_in.days < CERT_EXPIRE_CUTOFF_DAYS:
                log("Trying to renew cert {}".format(d['from']))
                cmd = "certbot certonly --verbose --noninteractive --preferred-challenges http --standalone --http-01-port {} --agree-tos -d {}".format(CERTBOT_PORT, SSL_CERT_FQDN)
                (out, err, exitcode) = run(cmd)
                
                if exitcode == 0:
                    log("RENEW SUCCESS: Certificate {} successfully renewed".format(d['from']))
    
                else:
                    log("RENEW FAIL: ERROR renewing certificate {}".format(d['from']))
                    log(out)
                    log(err)
                    
            
        cmd = 'certbot certonly --verbose --noninteractive --quiet --standalone  --http-01-port {} --agree-tos --email="{}" '.format(CERTBOT_PORT, SSL_CERT_EMAIL)
        cmd += ' -d "{}"'.format(SSL_CERT_FQDN)
    
        
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
                    log("Configured forwarding {} => {}".format(d['from'], d['to']))
        else:
            # write conf
            with open(conf_file, 'w') as f:
                f.write(proftpd_conf)
                log("Configured forwarding {} => {}".format(d['from'], d['to']))
    
def set_permissions():
    #run("chown -R ftpuser:ftpgroup {}".format(FTP_HOME_PATH))
    run("chmod -R 775 {}".format(FTP_HOME_PATH))
    
    
get_ssl_cert()
make_accounts()
set_permissions()