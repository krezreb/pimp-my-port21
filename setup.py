#!/usr/bin/env python

import os, json
import yaml_ordered as yo
from subprocess import Popen, PIPE
from OpenSSL import crypto
import datetime
from urlparse import urlparse
from urllib2 import urlopen
import socket
import crypt
import string, random
import argparse
import re

# FTP stuff
ACCOUNTS_REPORT_FILE = os.environ.get('ACCOUNTS_REPORT_FILE', None)
USER_CONF_PATH = os.environ.get('USER_CONF_PATH', None)
LIMITS_CONF_FILE = os.environ.get('LIMITS_CONF_FILE', '/etc/proftpd/conf.d/limits.conf')
FTP_HOME_PATH = os.environ.get('FTP_HOME_PATH', '/var/proftpd/home')
FTP_USERS_FILE = os.environ.get('FTP_USERS_FILE', '/var/proftpd/ftpusers')
SFTP_USERS_FILE = os.environ.get('SFTP_USERS_FILE', '/var/proftpd/sftpusers')
USER_KEYS_PATH = os.environ.get('USER_KEYS_PATH', '/var/proftpd/authorized_keys')
PASSWORD_STORE_PATH = os.environ.get('PASSWORD_STORE_PATH', '/var/proftpd/passwords')
PASSWORD_MIN_LENGTH = int(os.environ.get('PASSWORD_MIN_LENGTH', 10))

# optional default email to send account notifications to if none defined on conf or account level
ACCOUNT_DEFAULT_EMAIL = os.environ.get('ACCOUNT_DEFAULT_EMAIL', None)


# SSL cert stuff
ACME_CERT_PORT = os.environ.get('ACME_CERT_PORT', '80')
SSL_CERT_EMAIL = os.environ.get('SSL_CERT_EMAIL', None)
SSL_CERT_FQDN = os.environ.get('SSL_CERT_FQDN', None)
SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', '/var/ssl/domain')
SSL_CERT_SELF_SIGNED = os.environ.get('SSL_CERT_SELF_SIGNED', 'false').lower() in ["true", "on", "1", "yes"]
SSL_CERT_SELF_SIGNED_LIFESPAN_DAYS = os.environ.get('SSL_CERT_SELF_SIGNED_LIFESPAN_DAYS', 90)
CERT_EXPIRE_CUTOFF_DAYS = int(os.environ.get('CERT_EXPIRE_CUTOFF_DAYS', 31))

parser = argparse.ArgumentParser()
parser.add_argument('--port', default=ACME_CERT_PORT, help='What port to use to issue certs')
args = parser.parse_args()

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


class SetupSSL(object):

    def __init__(self, fqdn):
        self.my_ip = None
        self.fqdn = fqdn
        self.my_hostname = os.environ.get('MY_HOSTNAME', None)
        self.check_ip_url = os.environ.get('CHECK_IP_URL', 'http://ip.42.pl/raw')
        
    def points_to_me(self, s):
        self.get_my_ip()
        
        url = 'http://{}'.format(s)
        # from urlparse import urlparse  # Python 2
        parsed_uri = urlparse(url)
        domain = parsed_uri.netloc.split(':')[0]
        success = False
        ip = None
        try:
            ip = socket.gethostbyname(domain)
    
            if ip == self.my_ip:
                success = True
        except Exception as e:
            log(e)
            
        return (success, domain, ip, self.my_ip)

    def get_my_ip(self):
        
        if self.my_ip == None:
            self.my_ip = urlopen(self.check_ip_url).read()
    
            if self.my_hostname != None:
                ip = socket.gethostbyname(self.my_hostname)
                if ip != self.my_ip:
                    log("CONFIG ERROR: env var MY_HOSTNAME={} which resolves to ip {}. But according to {} my ip is {}".format(self.my_hostname, ip, self.check_ip_url, self.my_ip))
                    exit(-100)
                    
            log("My ip appears to be {}".format(self.my_ip))
    
        return self.my_ip
    
    def get_le_cert(self, cert_file, cert_email="you@example.com", expire_cutoff_days=31, acme_cert_http_port=80):
        change = False
        fail = False
        
        log('get_le_cert()')
        
        if os.path.isfile(cert_file):
            log('cert_file {} found'.format(cert_file))
            
            # cert already exists
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
            exp = datetime.datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
            
            expires_in = exp - datetime.datetime.utcnow()
            
            if expires_in.days <= 0:
                log("Found cert {} EXPIRED".format(self.fqdn))
            else:
                log("Found cert {}, expires in {} days".format(self.fqdn, expires_in.days))
        
            if expires_in.days < expire_cutoff_days:
                log("Trying to renew cert {}".format(self.fqdn))
                cmd = "acme.sh --renew --standalone --httpport {} -d {}".format(acme_cert_http_port, self.fqdn)
    
                (out, err, exitcode) = run(cmd)
                
                if exitcode == 0:
                    log("RENEW SUCCESS: Certificate {} successfully renewed".format(self.fqdn))
                    change = True
        
                else:
                    log("RENEW FAIL: ERROR renewing certificate {}".format(self.fqdn))
                    log(out)
                    log(err)
                    fail = True
        else :
            log('cert_file {} not found'.format(cert_file))
            cmd = "acme.sh --issue --standalone --httpport {} -d {}".format(acme_cert_http_port, self.fqdn)
    
            cmd += ' --accountemail {} '.format(cert_email)
            (out, err, exitcode) = run(cmd)
            
            if exitcode != 0:
                log("Requesting cert for {}: FAILED".format(self.fqdn))
                log(cmd)
                log(err)
                fail = True
    
            else:
                log("Requesting cert for {}: SUCCESS".format(self.fqdn))
                change = True
        
        return (change, fail)


class SetupAccounts(object):
    
    def __init__(self):
        self.ftp_users = []
        self.sftp_users = []
        self.limitsconf = []
        self.accounts = []
    
    def random_string(self, length=32):
        return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(length))
    
    def get_prefix(self, conf):
        try:
            prefix = conf['user_prefix']
        except KeyError:
            prefix = ""
            
        return prefix
    
    def prefix_transform(self, prefix):
        if prefix[-1] == "/":
            prefix = prefix[0:-1]
            
        valid_chars = '-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        out = ""
        for char in prefix:
            if char == "/":
                char = "_"
            if char in valid_chars:
                out += char
                
        return out
    
    def clean_home_path(self, home):
        return re.sub(r"(\/+)", "/", home)
    
    def get_home_and_username(self, username, user_dict, conf):
        prefix = self.get_prefix(conf)
        
        if len(prefix) > 0:
            username = "{}_{}".format(self.prefix_transform(prefix), username)
            
            try:
                home = prefix + '/' + user_dict['home']
            except:
                home = prefix + '/' + username
        
        else:
            try:
                home =  user_dict['home']
            except:
                home =  username
                if username[-3:] == "_ro":
                    home = home[:-3]
                            
        # http://www.proftpd.org/docs/howto/AuthFiles.html
        # username:password:uid:gid:gecos:homedir:shell
        
        username = self.username_transform(username)
        return (home, username)
    
    def username_transform(self, username):
        return username
    
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

        # limits_conf_file = '{}/.limits_conf_file'.format(FTP_HOME_PATH)
        
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
        
                    # with open(PROFTPD_USERS_FILE, "w") as fh:
                    
                    for raw_username, u in conf["users"].items():

                        (home, username) = self.get_home_and_username(raw_username, u, conf)
                        (password, isnew) = self.get_password(username)
                        
                        if len(password) < PASSWORD_MIN_LENGTH:
                            log("Password provided for user {} is less than the minimum {} characters, skipping".format(username, PASSWORD_MIN_LENGTH))
                            continue
                        
                        try:
                            # define protocols on yaml file level
                            protocols = conf['protocols']
                        except KeyError:
                            # if not on file level, blank slate
                            protocols = []
                            
                        if u != None:
                            try:
                                # protocol on account level
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
                                            line += ch
                                            if len(line) == 64:
                                                fac.write("{}\n".format(line))
                                                line = ""
                                        fac.write("{}\n".format(line))
                                        fac.write("---- END SSH2 PUBLIC KEY ----\n")
                                       
                                protocols.append('sftp')
                                             
                            except KeyError:
                                if len(protocols) == 0:
                                    protocols.append('ftp')  # no rsa key set so ftp
                        else:
                            if len(protocols) == 0:
                                protocols.append('ftp')  # no rsa key set so ftp
                            
                        hash = crypt.crypt(password, "$1${}".format(self.random_string(16)))
                        
                        abs_home = self.clean_home_path( FTP_HOME_PATH + '/' + home )
                        
                        # here we put 0 for uid and gid (root) because we don't care about perms here =) 
                        user_line = "{}:{}:0:0::{}:/bin/false".format(username, hash, abs_home)

                        if 'ftp' in protocols:
                            log("Authing user {} for ftp using their password".format(username))
                            self.ftp_users.append(user_line)
                        
                        
                           
                        if 'sftp' in protocols:
                            
                            if authorized_keys != None:
                                log("Authing user {} for sftp using their key(s)".format(username))
                                # an RSA key was specified, do not allow password auth
                                # this line puts in a password hash that will never work :D
                                user_line = "{}:{}:0:0::{}:/bin/false".format(username, '$1$RsaKeyConfigured', abs_home)
                            else:
                                log("Authing user {} for sftp using their password".format(username))
                                
                            self.sftp_users.append(user_line)
                                   
                        authorized_ips = []  # any ip allowed by default 
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
            
                        email = ACCOUNT_DEFAULT_EMAIL
                        
                        try:
                            email = u['email']
                        except:
                            try:
                                email = conf['email']
                            except:
                                pass
                        
                        readonly_user = False
        
                        if raw_username[-3:] == "_ro":
                            readonly_user = True
                            
                        '''
                        by default we init the account dict
                        with "u" so that any custom attributes are
                        passed along
                        '''
                        if u is None:
                            account = {}
                        else:
                            account = u
                                       
                        account["prefix"] = self.get_prefix(conf)
                        account["username"] = username
                        account["readonly_user"] = readonly_user
                        account["home"] = home
                        account["abs_home"]= abs_home
                        account["protocols"] = protocols
                        account["changed"] = isnew
                        account["password"] = password
                        
                            
                        if 'sftp' in protocols and authorized_keys != None:
                            account["authorized_keys"] = authorized_keys
                        
                        if authorized_ips != None:
                            account["authorized_ips"] = authorized_ips
                        if email != None:
                            account["email"] = email                               
                        
                        self.accounts.append(account)
        log("Done")
        return (change, fail)

    
if __name__ == '__main__':

    cert_file = SSL_CERT_PATH + '/cert.pem'
    s = SetupSSL(fqdn=SSL_CERT_FQDN)

    if SSL_CERT_SELF_SIGNED:
        if os.path.isfile(cert_file):
            # cert already exists
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
            exp = datetime.datetime.strptime(cert.get_notAfter(), '%Y%m%d%H%M%SZ')
            
            expires_in = exp - datetime.datetime.utcnow()

            log('cert_file {} found, expires in {} days'.format(cert_file, expires_in.days))

            if expires_in.days < CERT_EXPIRE_CUTOFF_DAYS:
                log('deleting cert_file')
                os.remove(cert_file)
        
        if not os.path.isfile(cert_file):
            if not os.path.isdir(SSL_CERT_PATH):
                os.makedirs(SSL_CERT_PATH)
        
            log('INFO: Generating self-signed ssl certificate')
            cmd = "openssl req -nodes -new -x509 -days {} -keyout {}/privkey.pem -out {}/cert.pem".format(SSL_CERT_SELF_SIGNED_LIFESPAN_DAYS, SSL_CERT_PATH, SSL_CERT_PATH)
            cmd += " -subj '/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN={}' ".format(SSL_CERT_FQDN)
            run(cmd)
        else:
            log('INFO: self-signed ssl certificate already exists')
            
        
    elif SSL_CERT_FQDN != None:
        (change, fail) = s.get_le_cert(cert_file, cert_email=SSL_CERT_EMAIL, expire_cutoff_days=CERT_EXPIRE_CUTOFF_DAYS, acme_cert_http_port=args.port)
                    
        
    if USER_CONF_PATH != None:
        if os.path.isdir(USER_CONF_PATH):
            log("Setting up users, USER_CONF_PATH={}".format(USER_CONF_PATH))
            s = SetupAccounts()
            s.make_accounts(user_conf_path=USER_CONF_PATH)
            
            with open(FTP_USERS_FILE, "w") as fh:
                fh.write("\n".join(s.ftp_users))
                
            with open(SFTP_USERS_FILE, "w") as fh:
                fh.write("\n".join(s.sftp_users))
                
            with open(LIMITS_CONF_FILE, "w") as fh:
                fh.write("\n".join(s.limitsconf))
                
            if ACCOUNTS_REPORT_FILE != None:
                with open(ACCOUNTS_REPORT_FILE, "w") as fh:
                    json.dump(s.accounts, fh, indent=4)
            
        else:
            log("Not setting up users, USER_CONF_PATH={}, but directory does not exist".format(USER_CONF_PATH))
            
    else:
        log("Not setting up users, USER_CONF_PATH not set")
            
