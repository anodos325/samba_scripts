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

DEBUG = False
DNS_TIMEOUT = 1

def get_config():
    conf = {}

    conf['cifs'] = Client().call('datastore.query', 'services.cifs', None, {'get': True})
    conf['ad'] = Client().call('datastore.query', 'directoryservice.activedirectory', None, {'get': True})
    conf['gc'] = Client().call('datastore.query', 'network.globalconfiguration', None, {'get': True})

    try:
        conf['ns'] = FreeNAS_ActiveDirectory.get_domain_controllers(conf['ad']['ad_domainname'], site=conf['ad']['ad_site']) 
    except:
        printf(f'Unable to get domain controllers for {conf["ad"]["ad_domainname"]}')
        sys_exit(1)

    conf['server_names'] = []
    conf['ns_ips'] = []
    conf['config_ns'] = []
    conf['config_ns'].append(conf['gc']['gc_nameserver1'])
    conf['config_ns'].append(conf['gc']['gc_nameserver2'])
    conf['config_ns'].append(conf['gc']['gc_nameserver3'])

    for name_server in conf['ns']:
        conf['ns_ips'].append(socket.gethostbyname(str(name_server.target)))

    conf['server_names'].append(conf['gc']['gc_hostname'] + "." + conf['ad']['ad_domainname'])
    
    if (conf['gc']['gc_hostname_b']) and (conf['gc']['gc_hostname_b'] != "truenas-b"):
       conf['server_names'].append(conf['gc']['gc_hostname_b'] + "." + conf['ad']['ad_domainname'])
    
    if (conf['gc']['gc_hostname_virtual']):
       conf['server_names'].append(conf['gc']['gc_hostname_virtual'] + "." + conf['ad']['ad_domainname'])

    return conf 


def validate_time(ntp_server):
    truenas_time = datetime.datetime.now()
    c = ntplib.NTPClient()
    try:
        response = c.request(ntp_server)
    except:
        return "error querying ntp_server"

    ntp_time = datetime.datetime.fromtimestamp(response.tx_time)

    clockskew = abs(ntp_time - truenas_time)

    return clockskew

def validate_ad_srv(alert_list, ad_domainname, name_servers, site=None, ssl=" off"):
    ad_domain_controllers = name_servers 
    kerberos_domain_controllers = FreeNAS_ActiveDirectory.get_kerberos_domain_controllers(ad_domainname, site)
    ldap_servers = FreeNAS_ActiveDirectory.get_ldap_servers(ad_domainname, site) 
    kpasswd_servers = FreeNAS_ActiveDirectory.get_kpasswd_servers(ad_domainname)
    global_catalog_servers = FreeNAS_ActiveDirectory.get_global_catalog_servers(ad_domainname, site, ssl)
    kerberos_servers = FreeNAS_ActiveDirectory.get_kerberos_servers(ad_domainname, site)

    for server in name_servers:
       get_server_status(str(server.target), 53, "Name", alert_list)

    for server in ad_domain_controllers:
       get_server_status(str(server.target), server.port, "AD/DC", alert_list)

    for server in ldap_servers:
       get_server_status(str(server.target), server.port, "LDAPS", alert_list)

    for server in kerberos_servers:
       get_server_status(str(server.target), server.port, "Kerberos", alert_list)

    for server in kerberos_domain_controllers:
       get_server_status(str(server.target), server.port, "KDC", alert_list)

    for server in global_catalog_servers:
       get_server_status(str(server.target), server.port, "Global Catalog", alert_list)

    return alert_list

def validate_dns(alert_list, server_names, name_server_ips):
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = name_server_ips 
    for server_name in server_names: 
      try:
          forward_lookup = my_resolver.query(server_name)
          server_address = str(forward_lookup.rrset).split()[4]
          if DEBUG:
              print(f'forward lookup for {server_name} successful')

      except:
          alert_list.append(f'address lookup for name {server_name} unsuccessful')
          if DEBUG:
              print(f'forward lookup for {server_name} unsuccessful')

    return alert_list

def get_server_status(host, port, server_type, alert_list):
    if not FreeNAS_ActiveDirectory.port_is_listening(host, port, timeout=DNS_TIMEOUT):
       if DEBUG:
           print(f'open socket to {server_type} Server {host} - Fail')

       alert_list.append(f'Failed to open socket to {server_type} Server {host}')

    else:
       if DEBUG:
           print(f'open socket to {server_type} Server {host} - Success')

    return alert_list

def validate_config(conf, alert_list):
    if conf['ad']['ad_domainname'] != conf['gc']['gc_domain']:
        alert_list.append(
            f'AD domain name {conf["ad"]["ad_domainname"]} does not match global conf domain {conf["gc"]["gc_domain"]}'
        ) 

    for config_nameserver in conf['config_ns']:
        if (config_nameserver) and (config_nameserver not in conf['ns_ips']):
            alert_list.append(
                f'{config_nameserver} is not a name server for AD domain {conf["ad"]["ad_domainname"]}'
            )

    return alert_list


def main():
    alert_list = []
    conf = get_config()
    validate_config(conf, alert_list)

    ad_permitted_clockskew = datetime.timedelta(minutes=1)
    for ad_domain_controller in conf['ns']:
       ad_permitted_clockskew = datetime.timedelta(minutes=1)
       ad_clockskew = validate_time(str(ad_domain_controller.target))
       if DEBUG:
           print(f'Clock skew from {ad_domain_controller.target} is {ad_clockskew}')

       try: 
           if ad_clockskew > ad_permitted_clockskew:
               alert_list.append(
                   f'Clock skew from {ad_domain_controller.target} is greater than 1 minute'
               )
       except:
           pass

    validate_ad_srv(alert_list, conf['ad']['ad_domainname'], conf['ns'],  site=conf['ad']['ad_site'], ssl=conf['ad']['ad_ssl'])
    validate_dns(alert_list, conf['server_names'], conf['ns_ips'])
    if alert_list:
        for alert in alert_list:
            print(alert)
    else:
        print("Success")
        return 0 


if __name__ == '__main__':
    main()
