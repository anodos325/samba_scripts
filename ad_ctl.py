#!/usr/local/bin/python
from middlewared.client import Client
from middlewared.service import Service, private

import os
import pwd
import re
import sys
import subprocess

if '/usr/local/www' not in sys.path:
    sys.path.append('/usr/local/www')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'freenasUI.settings')

import django
from django.apps import apps
if not apps.ready:
    django.setup()

from freenasUI.common.freenassysctl import freenas_sysctl as _fs
from freenasUI.common.freenasldap import FreeNAS_ActiveDirectory as FNAD
from freenasUI.common.freenasldap import FLAGS_DBINIT
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
    conf['cifs_srv'] = Client().call('datastore.query', 'services.services', [['srv_service','=','cifs']], {'get':True})
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
    if db['cifs']['cifs_srv_netbiosname'] == db['cifs']['cifs_srv_netbiosname_b']:
        '''
        Logic for checking if we've configured samba to only run on the active storage controller
        '''
        if not Client().call('notifier.failover_status') == "MASTER":
            return False

    if not db['ad']['ad_enable']:
        Client().call('datastore.update','directoryservice.ActiveDirectory', db['ad']['id'], {'ad_enable':'True'})
    if not db['cifs_srv']['srv_enable']:
        Client().call('datastore.update','services.services',db['cifs_srv']['id'], {'srv_enable':'True'}) 

    favored_dc = None
    dcs = FNAD.get_domain_controllers(
                                      db['ad']['ad_domainname'],
                                      site=db['ad']['ad_site'],
                                      ssl=db['ad']['ad_ssl']
                                     )

    '''
    For performing domain join / AD start, we minimize the amount
    of complex operations that we're performing. This avoiding an 
    extra LDAP bind here if possible.
    '''
    if len(dcs) <= 1:
        favored_dc = FNAD.get_best_host(dcs)
        print(f'favored dc is {favored_dc}')
    else:
        ''' 
        locate_site() requires an LDAP connection
        ''' 
        fn = FNAD(flags=FLAGS_DBINIT)
        print("locating site")
        site = fn.locate_site()
        dcs = fn.get_domain_controllers(db['ad']['ad_domainname'], site, ssl=db['ad']['ad_ssl'])
        if len(dcs) <= 5:
            favored_dc = FNAD.get_best_host(dcs)

    service_launcher("ix-hostname", "quietstart")
    try:
        krb_realm=(db['ad']['ad_kerberos_realm']['krb_realm'])
    except:
        krb_realm=(db['ad']['ad_domainname'])

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

    service_launcher("samba_server", "restart")
    Client().call('etc.generate', 'pam')
    service_launcher("ix-cache", "quietstart")

def stop():
    db = get_db_values()
    Client().call('datastore.update','directoryservice.ActiveDirectory', db['ad']['id'], {'ad_enable':'False'})
    Client().call('datastore.update','services.services',db['cifs_srv']['id'], {'srv_enable':'False'})
    service_launcher("samba_server", "stop")

def restart():
    db = get_db_values()
    if db['ad']['ad_unix_extensions']:
        service_launcher("ix-sssd", "start")
        if service_launcher("sssd", "status"):
            service_launcher("sssd", "restart")
        else:
            service_launcher("sssd", "start")

    service_launcher("ix-pre-samba", "start")   
    service_launcher("samba_server", "restart")
    if not Client().call('service.started', 'active.directory'):
        start()

def main():
    if len(sys.argv) == 2:
        if sys.argv[1] == "start":
            start()
        elif sys.argv[1] == "stop":
            stop()
        elif sys.argv[1] == "restart":
            restart() 
        else:
            return False

if __name__ == '__main__':
    main()
