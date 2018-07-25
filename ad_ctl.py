#!/usr/local/bin/python
from middlewared.client import Client

import os
import pwd
import re
import sys
import socket
import time
import ntplib
import datetime
import dns.resolver

if '/usr/local/www' not in sys.path:
    sys.path.append('/usr/local/www')

from freenasUI.common.freenassysctl import freenas_sysctl as _fs
from freenasUI.common.freenasldap import FreeNAS_ActiveDirectory
from freenasUI.common.pipesubr import pipeopen

def service_launcher(service, command):
    p = pipeopen("/usr/sbin/service %s %s" % (service, command))
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

def testjoin():


def main():
    db = get_db_values()
    service_launcher("ix-hostname", "quietstart")
    krb_realm=(db['ad']['ad_kerberos_realm']['krb_realm'])
    service_launcher("ix-kerberos", f'quietstart default {krb_realm}') 
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



if __name__ == '__main__':
    main()
