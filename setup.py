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

CHANGES_REPORT_FILE= os.environ.get('CHANGES_REPORT_FILE', None)
CERTBOT_PORT=os.environ.get('CERTBOT_PORT', '80')
USER_CONF_PATH=os.environ.get('USER_CONF_PATH', None)
LIMITS_CONF_FILE= os.environ.get('LIMITS_CONF_FILE', '/etc/proftpd/conf.d/limits.conf')
FTP_HOME_PATH = os.environ.get('FTP_HOME_PATH', '/var/proftpd/home')
FTP_USERS_FILE = os.environ.get('FTP_USERS_FILE', '/var/proftpd/ftpusers')
SFTP_USERS_FILE = os.environ.get('SFTP_USERS_FILE', '/var/proftpd/sftpusers')
USER_KEYS_PATH = os.environ.get('USER_KEYS_PATH', '/var/proftpd/authorized_keys')
PASSWORD_STORE_PATH = os.environ.get('PASSWORD_STORE_PATH', '/var/proftpd/passwords')
PASSWORD_MIN_LENGTH=int(os.environ.get('PASSWORD_MIN_LENGTH', 10))
SSL_CERT_EMAIL=os.environ.get('SSL_CERT_EMAIL', None)
SSL_CERT_FQDN=os.environ.get('SSL_CERT_FQDN', None)
SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', '/etc/letsencrypt/live')
SSL_CERT_SELF_SIGNED = os.environ.get('SSL_CERT_SELF_SIGNED', 'false').lower() in ["true", "on", "1", "yes"]
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



class Setup(object):
    
    def __init__(self):
        self.ftp_users = []
        self.sftp_users = []
        self.limitsconf = []
        self.changes = []
    
    def random_string(self, length=32):
        return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(length))

    def get_password(self, username):
        
        isnew = False
        
        if not os.path.isdir(PASSWORD_STORE_PATH):
            os.makedirs(PASSWORD_STORE_PATH)
            
        password_file = "{}/{}".format(PASSWORD_STORE_PATH, username)
        
        if not os.path.isfile(password_file):
            password = self.random_string()
            isnew = True
            
            with open(password_file, 'w') as fh:
                json.dump(password, fh)
                
        else:
            with open(password_file, 'r') as fh:
                password = json.load(fh)
            
        return (password, isnew)
        
    
    def make_accounts(self, user_conf_path=None):
        log("Start")
        
        change = False
        fail = False

        #limits_conf_file = '{}/.limits_conf_file'.format(FTP_HOME_PATH)
        
        self.limitsconf.append("<IfUser regex _ro$>\n<Limit WRITE>\nDenyAll\n</Limit>\n</IfUser>\n")
        
        if not os.path.isdir(user_conf_path):
            raise Exception("ERROR: User config dir {} does not exist, quitting".format(user_conf_path))
        
        for root, dirs, files in os.walk(user_conf_path):
            for file in files:
                if file.endswith(".yml"):
                    ymlfile = os.path.join(root, file)
                    try:
                        conf = yo.load(ymlfile)
                    except IOError:
                        log("ERROR: Error reading {}, quitting".format(ymlfile))
                        fail = True
                        continue
        
                    #with open(PROFTPD_USERS_FILE, "w") as fh:
                    
                    for raw_username, u in conf["users"].items():
            
                        username = raw_username
                        
                        try:
                            home = FTP_HOME_PATH+'/'+u['home']
                        except KeyError:
                            home = FTP_HOME_PATH+'/'+raw_username
                        
                        try:
                            prefix = conf['user_prefix']
                        except KeyError:
                            prefix = ""

                        readonly_user = False
            
                        if raw_username[-3:] == "_ro":
                            readonly_user = True
                            
                        
                        if len(prefix) > 0:
                            username = "{}_{}".format(prefix, raw_username)
                            
                            try:
                                home = FTP_HOME_PATH+'/'+prefix+'/'+u['home']
                            except KeyError:
                                home = FTP_HOME_PATH+'/'+prefix+'/'+raw_username
                                
                        
                        if raw_username[-3:] == "_ro":
                            home = home[:-3]
                                            
                        # http://www.proftpd.org/docs/howto/AuthFiles.html
                        # username:password:uid:gid:gecos:homedir:shell
                        
                        (password, isnew) = self.get_password(username)
                        
                        if len(password) < PASSWORD_MIN_LENGTH:
                            log("Password provided for user {} is less than the minimum {} characters, skipping".format(username, PASSWORD_MIN_LENGTH))
                            continue
                        
                        hash =  crypt.crypt(password, "$1${}".format(self.random_string(16)))
                        
                        # here we put 0 for uid and gid (root) because we don't care about perms here =) 
                        user_line = "{}:{}:0:0::{}:/bin/false".format(username,hash, home)
                        
                        protocols = []
                        if u != None:
                            try:
                                protocols = u['protocols']
                            except KeyError:
                                pass
                            
                        authorized_keys = None
                        if u != None:
                            try:
                                authorized_keys = u['authorized_keys']
                                keyfile = '{}/{}'.format(USER_KEYS_PATH, username)
                    
                                if not os.path.isdir(USER_KEYS_PATH):
                                    os.makedirs(USER_KEYS_PATH)
                                    
                                with open(keyfile, "w") as fac:
                                    for k in authorized_keys:
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
                            self.sftp_users.append(user_line)
                            
                        if 'ftp' in protocols:
                            log("Authing user {} for ftp using their password".format(username))
                            self.ftp_users.append(user_line)
                                   
                        authorized_ips = [] # any ip allowed by default 
                        try:
                            for ip in conf['authorized_ips']:
                                authorized_ips.append(ip)
                        except KeyError:
                            pass
                        
                        if u != None:
                            try:
                                for ip in u['authorized_ips']:
                                    authorized_ips.append(ip)
                            except KeyError:
                                pass
            
                        if len(authorized_ips) > 0:
                            self.limitsconf.append("<IfUser {}>\n<Limit LOGIN>\n".format(username))
                            for ip in authorized_ips:
                                self.limitsconf.append("Allow from {}\n".format(ip))
                            self.limitsconf.append("DenyAll\n</Limit>\n</IfUser>\n")
            
                        email = None
                        
                        try:
                            email = u['email']
                        except:
                            try:
                                email = conf['email']
                            except:
                                pass
                        
                        if isnew:
                            change = {
                                "prefix" : prefix,
                                "username" : username,
                                "readonly_user" : readonly_user,
                                "protocols" : protocols,
                            }
                            if 'ftp' in protocols:
                                change["password"] = password
                                
                            if 'sftp' in protocols and authorized_keys != None:
                                change["authorized_keys"] = authorized_keys
                                
                            if authorized_ips != None:
                                change["authorized_ips"] = authorized_ips
                            if email != None:
                                change["email"] = email                               
                            
                            self.changes.append(change)
        log("Done")
        return (change, fail)
    
def get_le_cert(cert_file, fqdn, cert_email="you@example.com", expire_cutoff_days=31, certbot_port=80):
    change = False
    fail = False
    
    log('get_le_cert()')
    
    cmd = "certbot certonly --verbose --noninteractive --preferred-challenges http --standalone --http-01-port {} --agree-tos -d {}".format(certbot_port, fqdn)
    
    if os.path.isfile(cert_file):
        log('cert_file {} found'.format(cert_file))
        
        # cert already exists
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
        exp = datetime.datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
        
        expires_in = exp - datetime.datetime.utcnow()
        
        if expires_in.days <= 0:
            log("Found cert {} EXPIRED".format(fqdn))
        else:
            log("Found cert {}, expires in {} days".format(fqdn, expires_in.days))
    
        if expires_in.days < expire_cutoff_days:
            log("Trying to renew cert {}".format(fqdn))
            (out, err, exitcode) = run(cmd)
            
            if exitcode == 0:
                log("RENEW SUCCESS: Certificate {} successfully renewed".format(fqdn))
                change = True
    
            else:
                log("RENEW FAIL: ERROR renewing certificate {}".format(fqdn))
                log(out)
                log(err)
                fail = True
    else :
        log('cert_file {} not found'.format(cert_file))

        cmd += ' --email="{}" '.format(cert_email)
        (out, err, exitcode) = run(cmd)
        
        if exitcode != 0:
            log("Requesting cert for {}: FAILED".format(fqdn))
            log(cmd)
            log(err)
            fail = True

        else:
            log("Requesting cert for {}: SUCCESS".format(fqdn))
            change = True
    
    return (change, fail)
    
    
    
if SSL_CERT_FQDN != None:
    cert_file=SSL_CERT_PATH+'/'+SSL_CERT_FQDN+'/cert.pem'
    (change, fail) = get_le_cert(cert_file, fqdn=SSL_CERT_FQDN, cert_email=SSL_CERT_EMAIL)
                
elif not os.path.isfile(SSL_CERT_PATH+'/domain/cert.pem') and SSL_CERT_SELF_SIGNED:
    if not os.path.isdir(SSL_CERT_PATH+'/domain'):
        os.makedirs(SSL_CERT_PATH+'/domain')
    
    log('INFO: Generating self-signed ssl certificate')
    cmd = "openssl req -nodes -new -x509 -keyout {}/privkey.pem -out {}/cert.pem".format(SSL_CERT_PATH+'/domain', SSL_CERT_PATH+'/domain')
    cmd += " -subj '/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com' "
    run(cmd)
    
if USER_CONF_PATH != None:
    if os.path.isdir(USER_CONF_PATH):
        log("Setting up users, USER_CONF_PATH={}".format(USER_CONF_PATH))
        s = Setup()
        s.make_accounts(user_conf_path=USER_CONF_PATH)
        
        with open(FTP_USERS_FILE, "w") as fh:
            fh.write("\n".join(s.ftp_users))
            
        with open(SFTP_USERS_FILE, "w") as fh:
            fh.write("\n".join(s.sftp_users))
            
        with open(LIMITS_CONF_FILE, "w") as fh:
            fh.write("\n".join(s.limitsconf))
            
        if CHANGES_REPORT_FILE != None:
            with open(CHANGES_REPORT_FILE, "w") as fh:
                json.dump(s.changes, fh, indent=4)
        
    else:
        log("Not setting up users, USER_CONF_PATH={}, but directory does not exist".format(USER_CONF_PATH))
        
        
else:
    log("Not setting up users, USER_CONF_PATH not set")
            
