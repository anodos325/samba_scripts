#!/usr/local/bin/python
from middlewared.client import Client
from middlewared.service import Service, private

import os
import pwd
import re
import sys
import socket
import time
import ntplib
import datetime
import dns.resolver
import subprocess

if '/usr/local/www' not in sys.path:
    sys.path.append('/usr/local/www')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'freenasUI.settings')

import django
from django.apps import apps
if not apps.ready:
    django.setup()

from freenasUI.common.freenassysctl import freenas_sysctl as _fs
from freenasUI.common.freenasldap import FreeNAS_ActiveDirectory
from freenasUI.common.pipesubr import pipeopen

NETCMD = "/usr/local/bin/net -k -d 5 ads"
JOINLOG = "/var/log/samba4/ad_join.log"

def service_launcher(service, command):
    print(f'executing command {service}, {command}')
    p = pipeopen(f'/usr/sbin/service {service} {command}')
    output = p.communicate()
    if p.returncode != 0:
        print("Service %s failed on command %s " % (service, command))
        return False
    return True

def get_db_values():
    conf = {} 
    conf['ad'] = Client().call('datastore.query', 'directoryservice.ActiveDirectory', None, {'get': True})
    conf['ldap'] = Client().call('datastore.query', 'directoryservice.LDAP', None, {'get':True})
    conf['cifs'] = Client().call('datastore.query', 'services.cifs', None, {'get':True})
    return conf

def netads(db, command, bind_dc):
    domain = db['ad']['ad_domainname']
    if bind_dc:
        p = pipeopen(f'{NETCMD} {command} {domain} -S {bind_dc[0]} -p {bind_dc[1]}')
        output = p.communicate()
        with open(JOINLOG, "w") as f:
            f.write(str(output[1]))

        if p.returncode == 0:
            return True

        return False
    else:
        p = pipeopen(f'{NETCMD} {command} {domain}')
        output = p.communicate()
        if p.returncode == 0:
            return True

        return False

def start():
    db = get_db_values()
    favored_dc = None
    dcs = FreeNAS_ActiveDirectory.get_domain_controllers(
                                                         db['ad']['ad_domainname'],
                                                         site=db['ad']['ad_site'], 
                                                         ssl=db['ad']['ad_ssl']
                                                        )

    if len(dcs) <= 10:
        favored_dc = FreeNAS_ActiveDirectory.get_best_host(dcs)
        print(f'favored dc is {favored_dc}')

    service_launcher("ix-hostname", "quietstart")
    krb_realm=(db['ad']['ad_kerberos_realm']['krb_realm'])
    service_launcher("ix-kerberos", command=f'quietstart default {krb_realm}') 

    Client().call('etc.generate', 'nss')

    if db['ldap']['ldap_enable']:
        print('generating ldap_conf')
        Client().call('etc.generate', 'ldap')

    if not service_launcher("ix-kinit", "status"):
        if not service_launcher("ix-kinit", "quietstart"):
            print("ix-kinit failed")

    if db['ad']['ad_unix_extensions']:
        service_launcher("ix-sssd", "start")
        if service_launcher("sssd", "status"):
            service_launcher("sssd", "restart")
        else:
            service_launcher("sssd", "start")

    service_launcher("ix-pre-samba", "start")   

    if not netads(db, "testjoin", bind_dc=favored_dc):
        print('preparing to join domain')
        netads(db, "join", bind_dc=favored_dc)

    Client().call('service.reload', 'activedirectory')
    Client().call('etc.generate', 'pam')
    service_launcher("ix-cache", "quietstart")

def stop():
    db = get_db_values

def main():
    start()

if __name__ == '__main__':
    main()
