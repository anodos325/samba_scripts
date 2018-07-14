#!/usr/local/bin/python
from middlewared.client import Client
from middlewared.client.utils import Struct

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

def validate_time(ntp_server):
    truenas_time = datetime.datetime.now()
    c = ntplib.NTPClient()
    try:
        response = c.request(ntp_server)
    except:
        return "error querying ntp_server"

    ntp_time = datetime.datetime.fromtimestamp(response.tx_time)

    if ntp_time > truenas_time:
        clockskew = ntp_time - truenas_time
    else:
        clockskew = truenas_time - ntp_time

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
      except:
          alert_list.append(f'address lookup for name {server_name} unsuccessful')

    return alert_list

def get_server_status(host, port, server_type, alert_list):
    if not FreeNAS_ActiveDirectory.port_is_listening(host, port, timeout=1):
       alert_list.append(f'Failed to open socket to {server_type} Server {host}')
    return alert_list

def main():
    #####################################
    # Grab information from Config File #
    #####################################
    server_names = []
    alert_list = []
    config_nameservers = []

    ngc = Struct(Client().call('datastore.query', 'network.globalconfiguration', None, {'get': True}))
    cifs = Struct(Client().call('datastore.query', 'services.cifs', None, {'get': True}))
    ad = Struct(Client().call('datastore.query', 'directoryservice.activedirectory', None, {'get': True})) 

    cifs_srv_bind_ip = cifs.cifs_srv_bindip

    server_names.append(ngc.gc_hostname + "." + ad.ad_domainname)

    if (ngc.gc_hostname_b) and (ngc.gc_hostname_b != "truenas-b"):
       server_names.append(ngc.gc_hostname_b + "." + ad.ad_domainname)

    if (ngc.gc_hostname_virtual):
       server_names.append(ngc.gc_hostname_virtual + "." + ad.ad_domainname)

    config_nameservers.append(ngc.gc_nameserver1)
    config_nameservers.append(ngc.gc_nameserver2)
    config_nameservers.append(ngc.gc_nameserver3)

    #############################
    # CONFIG SANITY CHECKS      #
    #############################
    name_servers = FreeNAS_ActiveDirectory.get_domain_controllers(ad.ad_domainname, site=ad.ad_site)

    # See if domain name is set inconsistently
    if ad.ad_domainname != ngc.gc_domain:
        alert_list.append(
            f'AD domain name {ad.ad_domainname} does not match global config domain {ngc.gc_domain}'
        )

    # See if we've set name servers that aren't for our domain
    name_server_ips = []
    for name_server in name_servers:
       name_server_ips.append(socket.gethostbyname(str(name_server.target)))

    for config_nameserver in config_nameservers:
        if (config_nameserver) and (config_nameserver not in name_server_ips):
            alert_list.append(f'{config_nameserver} is not a name server for AD domain {ad.ad_domainname}')

    #############################
    #  NTP CHECKS               #
    #############################

    ## Compare clock skew between system time and DC time ##
    ad_permitted_clockskew = datetime.timedelta(minutes=1)
    for ad_domain_controller in name_servers:
       ad_permitted_clockskew = datetime.timedelta(minutes=1)
       ad_clockskew = validate_time(str(ad_domain_controller.target))
       try: 
           if ad_clockskew > ad_permitted_clockskew:
               alert_list.append(
                   f'Clock skew from {ad_domain_controller.target} is greater than 1 minute'
               )
       except:
           pass

    #############################
    # DNS  CHECKS               #
    #############################

    validate_ad_srv(alert_list, ad.ad_domainname, name_servers,  site=ad.ad_site, ssl=ad.ad_ssl)
    validate_dns(alert_list, server_names, name_server_ips)
    if alert_list:
        for alert in alert_list:
            print(alert)
    else:
        print("Everything works! Yay!")

if __name__ == '__main__':
    main()
