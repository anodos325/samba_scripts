#!/usr/local/bin/python

import os
import pwd
import re
import sys
import socket
import subprocess
import tempfile
import time
import logging
import logging.config
import ntplib
import datetime
import sqlite3
import dns.resolver
import textwrap

if '/usr/local/www' not in sys.path:
    sys.path.append('/usr/local/www')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'freenasUI.settings')

import django
from django.apps import apps
if not apps.ready:
    django.setup()

from freenasUI.common.freenassysctl import freenas_sysctl as _fs
from freenasUI.common.freenasldap import FreeNAS_ActiveDirectory

def validate_time(ntp_server):
    # to do: should use UTC instead of local time. On other hand,
    # this is not a big con for a manual smoke-test.

    truenas_time = datetime.datetime.now()
    c = ntplib.NTPClient()
    try:
        response = c.request(ntp_server)
    except:
        return "error querying ntp_server"

    ntp_time = datetime.datetime.fromtimestamp(response.tx_time)

    # I'm only concerned about clockskew and not who is to blame.
    if ntp_time > truenas_time:
        clockskew = ntp_time - truenas_time
    else:
        clockskew = truenas_time - ntp_time

    return clockskew


def get_server_status(host, port, server_type):
    if FreeNAS_ActiveDirectory.port_is_listening(host, port):
       print("DEBUG: open socket to %s Server %s reports - SUCCESS" % (server_type, host))
    else:
       print("DEBUG: open socket to %s Server %s reports - FAIL" % (server_type, host))

def main():
    #####################################
    # Grab information from Config File #
    #####################################
    server_names = []
    bind_ips = []
    FREENAS_DB = '/data/freenas-v1.db'
    conn = sqlite3.connect(FREENAS_DB)
    conn.row_factory = lambda cursor, row: row[0]
    c = conn.cursor()

    # Get NTP Servers
    c.execute('SELECT ntp_address FROM system_ntpserver')
    config_ntp_servers = c.fetchall()

    # Get IP Addresses for NICs
    c.execute('SELECT int_ipv4address FROM network_interfaces')
    config_ipv4_addresses = c.fetchall()

    c.execute('SELECT cifs_srv_bindip FROM services_cifs')
    cifs_srv_bind_ip = c.fetchone()

    if (cifs_srv_bind_ip):
       bind_ips = str(cifs_srv_bind_ip).split(",")
    else:
       bind_ips = config_ipv4_addresses
    
    # Get AD domain name
    c.execute('SELECT ad_domainname FROM directoryservice_activedirectory')
    ad_domainname = c.fetchone()

    # Get Global Configuration Domain Network
    c.execute('SELECT gc_domain FROM network_globalconfiguration')
    gc_domain = c.fetchone()

    c.execute('SELECT gc_hostname FROM network_globalconfiguration')
    gc_hostname = c.fetchone()

    c.execute('SELECT gc_hostname_b FROM network_globalconfiguration')
    gc_hostname_b = c.fetchone()

    c.execute('SELECT gc_hostname_virtual FROM network_globalconfiguration')
    gc_hostname_virtual = c.fetchone()
    
    server_names.append(gc_hostname + "." + ad_domainname)

    if (gc_hostname_b) and (gc_hostname_b != "truenas-b"):
       server_names.append(gc_hostname_b + "." + ad_domainname)

    if (gc_hostname_virtual):
       server_names.append(gc_hostname_virtual + "." + ad_domainname)

    # Get config DNS servers
    c.execute('SELECT gc_nameserver1 FROM network_globalconfiguration')
    config_nameserver1 = c.fetchone()
    c.execute('SELECT gc_nameserver2 FROM network_globalconfiguration')
    config_nameserver2 = c.fetchone()
    c.execute('SELECT gc_nameserver3 FROM network_globalconfiguration')
    config_nameserver3 = c.fetchone()
    conn.close()

    #####################################
    # DNS query all the things          #
    #####################################
    ad_domain_controllers = FreeNAS_ActiveDirectory.get_domain_controllers(ad_domainname)
    kerberos_domain_controllers = FreeNAS_ActiveDirectory.get_kerberos_domain_controllers(ad_domainname)
    name_servers = ad_domain_controllers 
    ldap_servers = FreeNAS_ActiveDirectory.get_ldap_servers(ad_domainname) 
    kpasswd_servers = FreeNAS_ActiveDirectory.get_kpasswd_servers(ad_domainname)
    global_catalog_servers = FreeNAS_ActiveDirectory.get_global_catalog_servers(ad_domainname)
    kerberos_servers = FreeNAS_ActiveDirectory.get_kerberos_servers(ad_domainname)

    #############################
    # CONFIG SANITY CHECKS      #
    #############################

    # See if domain name is set inconsistently
    if ad_domainname != gc_domain:
        print("WARNING: AD domain name %s does not match global configuration domain %s" % (ad_domainname, gc_domain))

    # See if we've set name servers that aren't for our domain
    name_server_ips = []
    for name_server in name_servers:
       name_server_ips.append(socket.gethostbyname(str(name_server.target)))

    if (config_nameserver1) and (config_nameserver1 not in name_server_ips):
       print("WARNING: name server %s is not a name server for AD domain %s" % (config_nameserver1,ad_domainname))

    if (config_nameserver2) and (config_nameserver2 not in name_server_ips):
       print("WARNING: name server %s is not a name server for AD domain %s" % (config_nameserver2,ad_domainname))

    if (config_nameserver3) and (config_nameserver3 not in name_server_ips):
       print("WARNING: name server %s is not a name server for AD domain %s" % (config_nameserver3,ad_domainname))


    #############################
    #  NTP CHECKS               #
    #############################

    ## Compare clockskew between system time and config ntp server time ##
    config_permitted_clockskew = datetime.timedelta(minutes=1)
    print("DEBUG: determining clock skew between NAS and configured NTP servers")
    for ntp_server in config_ntp_servers:
       config_clockskew = validate_time(ntp_server)
       print("CONFIG_NTP_SERVERS: %s clockskew is: %s" % (ntp_server,config_clockskew))
       try: 
           if config_clockskew > config_permitted_clockskew:
               print("   WARNING: clockskew between configured NTP server and system time is greater than 1 minute")
       except:
           pass

    ## Compare clock skew between system time and DC time ##
    ad_permitted_clockskew = datetime.timedelta(minutes=1)
    for ad_domain_controller in ad_domain_controllers:
       ad_clockskew = validate_time(str(ad_domain_controller.target))
       print("AD_NTP_SERVERS: %s clockskew is: %s" % (ad_domain_controller.target,ad_clockskew))
       try: 
           if ad_clockskew > ad_permitted_clockskew:
               print("   WARNING: clock skew between AD DC and system time is greater than 1 minute")
       except:
           pass


    #############################
    # DNS  CHECKS               #
    #############################

    # Verify that we can open sockets to the various AD components
    for server in name_servers:
       get_server_status(str(server.target), 53, "Name")

    for server in ad_domain_controllers:
       get_server_status(str(server.target), server.port, "AD/DC")

    for server in ldap_servers:
       get_server_status(str(server.target), server.port, "LDAPS")

    for server in kerberos_servers:
       get_server_status(str(server.target), server.port, "Kerberos")

    for server in kerberos_domain_controllers:
       get_server_status(str(server.target), server.port, "KDC")

    for server in global_catalog_servers:
       get_server_status(str(server.target), server.port, "Global Catalog")

    print("DEBUG: Verifying server entries in IPv4 forward lookup zone")
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = name_server_ips 
    for server_name in server_names: 
      try:
          forward_lookup = my_resolver.query(server_name)
          server_address = str(forward_lookup.rrset).split()[4]
          print("   SUCCESS - %s resolved to %s" % (server_name, server_address)) 
      except:
          print("   FAIL - address lookup for name %s unsuccessful" % (server_name))

    print("DEBUG: Verifying server entries in IPv4 reverse lookup zone")
    for address in bind_ips:
       try:
          host_name = socket.gethostbyaddr(address)
          print("   SUCCESS - %s resolved to %s" % (address, host_name[0]))
       except:
          print("   FAIL - hostname lookup for address %s unsuccessful" % (address))


if __name__ == '__main__':
    main()
